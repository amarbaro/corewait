#!/usr/bin/env bash
# CPU-only gate, no phone or laptop needed: build, record smoke on this machine, then the analyzer on frozen fixtures.
# Usage: ./check.sh        (CW_NO_RECORD=1: skip the probe build and record, for a machine without perf counters; capture: ./check.sh 2>&1 | tee .work/C-gate.txt; echo ${PIPESTATUS[0]})
set -euo pipefail
GW=""; command -v gpu-wait > /dev/null && GW="gpu-wait run --shared --vram 1 --timeout 600 --"
cd "$(dirname "$0")"
fail() { echo "FAIL $1: $2"; exit 1; }
mkdir -p build .work
mb() {  # mojo build opens the GPU even for CPU code
    $GW mojo build "$1" -o "$2" > "$2.log" 2>&1 \
        || fail "build $2" "$(grep -m3 error "$2.log") (log $2.log)"
}
if [ -n "${CW_NO_RECORD:-}" ]; then mb src/corewait.mojo build/corewait-an; echo "ok 1 build (analyzer only)"
else
./corewait build desktop &
mb src/corewait.mojo build/corewait-an &
wait -n && wait -n || fail build "see build/*.log"
echo "ok 1 build"

# 2. record: the chase probe's hottest cycles address lies in chase_k, and all four event roles and the stat file exist
rm -rf .work/rec-chase
./corewait record desktop .work/rec-chase -- build/cwprobe-desktop chase
gawk -F'\t' '
    FILENAME ~ /samples/ { role[$1] = 1; if ($1 == "cycles" && $4 > best) { best = $4; at = strtonum("0x" $3) } next }
    /^[0-9a-f]+ </ { a = strtonum("0x" $1); if (in_fn) end = a; in_fn = ($0 ~ /chase_k/); if (in_fn) start = a; next }
    END { if (!(start <= at && at < end)) { print "FAIL record: hottest cycles at " at " outside chase_k " start "-" end; exit 1 }
          for (r in need) if (!(r in role)) { print "FAIL record: no " r " samples"; exit 1 } }
    BEGIN { need["cycles"]; need["mem"] }' .work/rec-chase/samples.tsv .work/rec-chase/objdump.txt
for k in cycles instructions slots fe be ret; do grep -q "^$k	" .work/rec-chase/stat.tsv || fail record "stat.tsv has no $k"; done
echo "ok 2 record desktop chase"
# a python host: a script BINARY reports its hottest library, a running process is sampled by --pid, pick moves to another library without a run
cat > .work/host.py <<'PY'
#!/usr/bin/env python3
import hashlib, sys, time
end = time.time() + float(sys.argv[1])
while time.time() < end: hashlib.sha256(b"x" * 65536).digest()
PY
chmod +x .work/host.py; rm -rf .work/rec-host .work/rec-pid
./corewait record desktop .work/rec-host --no-stat -- .work/host.py 1 >/dev/null
[ "$(gawk -F'\t' '$1 == "binary" { print $2 }' .work/rec-host/meta.txt)" = "$(sed -n 1p .work/rec-host/dsos.tsv | cut -f3 | xargs basename)" ] || fail host "binary is not the hottest library"
./corewait show .work/rec-host --top 1 | grep -q "^fn" || fail host "show printed no function"
./corewait pick .work/rec-host "$(sed -n 2p .work/rec-host/dsos.tsv | cut -f3)" || fail host pick
n=$(wc -l < .work/rec-host/samples.tsv); ./corewait pick .work/rec-host /usr/bin/true > /dev/null 2>&1 && fail host "pick of an unsampled library passed"
[ "$(wc -l < .work/rec-host/samples.tsv)" = "$n" ] || fail host "a failed pick emptied samples.tsv"
cat > .work/argv.py <<'PY'
#!/usr/bin/env python3
import hashlib, os, sys, time
open(os.environ["CW_OUT"], "w").write(repr(sys.argv[1:]) + " " + os.environ["CW_SP"])
end = time.time() + 0.5
while time.time() < end: hashlib.sha256(b"x" * 65536).digest()
PY
chmod +x .work/argv.py; rm -rf ".work/rec q"
./corewait record desktop ".work/rec q" --no-stat -- env CW_OUT=.work/argv.txt CW_SP='x y' .work/argv.py 'a b' "c'd" > /dev/null
[ "$(cat .work/argv.txt)" = "['a b', \"c'd\"] x y" ] || fail record "args or K=V split: $(cat .work/argv.txt)"
m=$(./corewait record desktop .work/rec-none -- no_such_cmd_cw argA 2>&1) && fail record "a missing command passed"
[[ "$m" == "FAIL record: no_such_cmd_cw is not"* ]] || fail record "missing command misnamed: $m"
.work/host.py 4 & hp=$!; sleep 0.5; ./corewait record desktop .work/rec-pid --pid "$hp" -- sleep 1 >/dev/null; wait "$hp"
[ -s .work/rec-pid/samples.tsv ] || fail host "--pid gave no samples"
echo "ok 2b python host: script, pick, --pid, a failed pick keeps the report, args and K=V with spaces, a path with a space"
# 2b. `-- env K=V BINARY`: the pairs reach the program, the profiled and objdumped binary stays BINARY (not env)
rm -rf .work/rec-env
./corewait record desktop .work/rec-env -- env CW_CHECK=1 build/cwprobe-desktop chase >/dev/null
grep -q "^binary	cwprobe-desktop$" .work/rec-env/meta.txt || fail record "env form: meta names $(grep ^binary .work/rec-env/meta.txt)"
grep -q "^command	.*env CW_CHECK=1 " .work/rec-env/meta.txt || fail record "env form: K=V missing from the command"
grep -q "chase_k" .work/rec-env/objdump.txt && [ -s .work/rec-env/samples.tsv ] || fail record "env form: no samples or wrong objdump"
echo "ok 2b record -- env K=V BINARY"
fi

# 3. the analyzer on the committed fixtures prints the frozen tables byte for byte (FREEZE=1 rewrites fixtures/golden), the
#    cause cycles sum to the raw total, and each probe's top cause is the intended one
mkdir -p fixtures/golden
declare -A top=([chase]=mem [stream]=mem [fmachain]=dep [branchy]=branch)
for d in fixtures/*-*/; do
    d=${d%/}; n=$(basename "$d"); [ "$n" = golden ] && continue
    ./corewait show "$d" --top 12 > ".work/$n.txt"; ./corewait show "$d" --causes --fn "${n#*-}_k" > ".work/$n-causes.txt"
    if [ -n "${FREEZE:-}" ]; then cp ".work/$n.txt" ".work/$n-causes.txt" fixtures/golden/; fi
    cmp -s ".work/$n.txt" "fixtures/golden/$n.txt" || { diff ".work/$n.txt" "fixtures/golden/$n.txt" | head -5; fail golden "$n table differs"; }
    cmp -s ".work/$n-causes.txt" "fixtures/golden/$n-causes.txt" || fail golden "$n causes differ"
    # 4. causes sum to the raw total, and the top cause is the probe's
    gawk -v n="$n" -v want="${top[${n#*-}]:-}" '$1 ~ /^(mem|fe|dep|branch|busy)$/ { if ($2 + 0 > best) { best = $2 + 0; got = $1 } } $1 == "total" { if ($2 != $4) { print "FAIL causes: " n " total " $2 " != raw " $4; exit 1 } }
        END { if (want != "" && got != want) { print "FAIL causes: " n " top cause " got ", want " want; exit 1 } }' ".work/$n-causes.txt"
done
echo "ok 3 golden tables, cause sums, top causes"

# 4. mutant: the skid rule off (--k 0) must change every device's chase table
for d in fixtures/*-chase; do
    n=$(basename "$d"); ./corewait show "$d" --top 12 --k 0 > ".work/mutant-$n.txt"
    cmp -s ".work/mutant-$n.txt" "fixtures/golden/$n.txt" && fail mutant "skid rule off left the $n table unchanged"
done
echo "ok 4 mutant: skid off changes the chase table on every device"

# 5. diff: a fixture against itself changes no row; two devices' chase fixtures align on the load and match the frozen diff
./corewait diff fixtures/desktop-chase fixtures/desktop-chase > .work/diff-self.txt
grep -q "(+0.0%), rows changed 0" .work/diff-self.txt || fail diff "a fixture against itself is not all zero: $(head -1 .work/diff-self.txt)"
./corewait diff fixtures/desktop-chase fixtures/laptop-chase --top 12 > .work/diff-chase.txt
if [ -n "${FREEZE:-}" ]; then cp .work/diff-chase.txt fixtures/golden/diff-desktop-laptop-chase.txt; fi
cmp -s .work/diff-chase.txt fixtures/golden/diff-desktop-laptop-chase.txt || fail golden "diff desktop-laptop chase differs"
gawk '/mov rax, qword ptr \[rdi \+ 8\*rax\]/ { ok = ($3 > 0 && $4 > 0 && $5 == $4 - $3) } END { exit !ok }' .work/diff-chase.txt || fail diff "the chase load is not aligned across devices"
# one name with two instantiations (Mojo's, cut at "("): each row once (it was aligned once per instantiation)
./corewait diff fixtures/dupname/a fixtures/dupname/b > .work/diff-dup.txt
grep -q "rows changed 1$" .work/diff-dup.txt || fail diff "a repeated function name counted its rows twice: $(head -1 .work/diff-dup.txt)"
echo "ok 5 diff: self is zero, cross-device chase load aligned, frozen, repeated names once"

# 6. budget passes and fails on two prepared files
./corewait budget fixtures/desktop-chase fixtures/budget/pass.txt > .work/budget-pass.txt || fail budget "pass.txt breached: $(cat .work/budget-pass.txt)"
if ./corewait budget fixtures/desktop-chase fixtures/budget/fail.txt > .work/budget-fail.txt; then fail budget "fail.txt did not breach"; fi
grep -q "^FAIL budget: chase_k mem" .work/budget-fail.txt || fail budget "fail.txt printed no breach line"
echo "ok 6 budget: pass.txt exits 0, fail.txt exits 1"

# 7. speed of light: show --bytes/--bw on the desktop stream fixture agrees with the probe's own GB/s and matches the frozen line
bytes=$(gawk '{ for (i = 1; i < NF; i++) if ($i == "steps") print $(i + 1) }' fixtures/desktop-stream/run.txt)
probe=$(gawk '/GBps/ { print $NF }' fixtures/desktop-stream/run.txt)
bw=$(gawk -F'|' '$2 == " desktop " { gsub(/ /, "", $4); print $4 }' docs/DEVICES.md)
./corewait show fixtures/desktop-stream --fn stream_k --bytes "$bytes" --bw "$bw" --top 3 > .work/sol.txt
if [ -n "${FREEZE:-}" ]; then cp .work/sol.txt fixtures/golden/desktop-stream-sol.txt; fi
cmp -s .work/sol.txt fixtures/golden/desktop-stream-sol.txt || fail golden "the sol output differs"
gawk -v probe="$probe" -v bw="$bw" '/^sol:/ { for (i = 1; i < NF; i++) if ($i == "GB/s,") got = $(i - 1); exit } END { exit !(got > probe * 0.75 && got < probe * 1.25) }' .work/sol.txt \
    || fail sol "$(grep '^sol:' .work/sol.txt) is not within 25% of the probe's $probe GB/s"
echo "ok 7 speed of light: $(grep '^sol:' .work/sol.txt | cut -d= -f2 | cut -c2-) (probe $probe GB/s, bw $bw)"

# 8. performance: a 1M-row samples.tsv, show under 1 s and 200 MB
mkdir -p .work/perf1m
cp fixtures/desktop-stream/{objdump.txt,stat.tsv} .work/perf1m/
gawk 'BEGIN { srand(1) } /^ +[0-9a-f]+:/ { a = $1; sub(/:$/, "", a); addr[n++] = a }
    END { split("cycles cycles cycles cycles mem fe br", ev, " "); for (i = 0; i < 1000000; i++) printf "%s\tcwprobe-desktop\t%s\t%d\n", ev[1 + int(rand() * 7)], addr[int(rand() * n)], 1000 }' \
    .work/perf1m/objdump.txt > .work/perf1m/samples.tsv
/usr/bin/time -f "%e %M" -o .work/perf1m/time.txt ./build/corewait-an show .work/perf1m > /dev/null
read -r secs kb < .work/perf1m/time.txt
echo "perf: 1000000 rows, show $secs s, peak RSS $((kb / 1024)) MB"
gawk -v s="$secs" -v kb="$kb" 'BEGIN { exit !(s < 1 && kb < 204800) }' || fail perf "show took $secs s, peak $((kb / 1024)) MB (limits 1 s, 200 MB)"
echo "ok 8 performance"
# 9. a row past 2^39 cycles (a long or merged run) still ranks first (a 64-bit sort key overflowed: it ranked last)
./corewait show fixtures/bigcount --top 2 > .work/bigcount.txt
gawk '$1 == "addr" { getline; exit !($1 == "1000") }' .work/bigcount.txt || fail sort "the 1e12-cycle row is not first: $(grep -A1 "^ *addr" .work/bigcount.txt | tail -1)"
echo "ok 9 a 1e12-cycle row ranks first"

# 10. an event perf could not count: stat.tsv leaves its role out (it wrote "<not counted>", which show died on) and
#    derives no share from it (a missing backend made retiring 98%)
mkdir -p .work/stat9
for f in fixtures/statraw/*.raw; do
    n=$(basename "$f" .raw); rm -rf ".work/stat9/$n"; mkdir -p ".work/stat9/$n"; cp "$f" ".work/stat9/$n/stat.raw"
    ./corewait stat desktop ".work/stat9/$n"
    gawk -F'\t' '$1 !~ /^(note|p_)/ && $2 !~ /^[0-9]+$/ { exit 1 }' ".work/stat9/$n/stat.tsv" || fail stat "$n: a non-numeric count in stat.tsv"
done
grep -q "^ret" .work/stat9/not-supported/stat.tsv && fail stat "retiring derived without a backend count"
cp fixtures/desktop-chase/{objdump.txt,samples.tsv} .work/stat9/not-counted/
./corewait show .work/stat9/not-counted --top 1 > .work/stat9/show.txt || fail stat "show on a stat.tsv with an uncounted event"
echo "ok 10 uncounted events: left out, no share derived from them"

# 11. diff of a function too big for the O(nm) table: two 7,000-row builds (49M cells, over the 40M default cap) with distinct rows,
#    a 1.4 MB mangled branch target on each side (a real objdump line), cycles conserved, linear memory, and the same output as the table
rm -rf .work/big; mkdir -p .work/big/a .work/big/b
gawk -v dir=.work/big -v n=7000 'BEGIN {
    sym = sprintf("%1400000s", ""); gsub(/ /, "x", sym)
    for (s = 0; s < 2; s++) {
        d = dir "/" (s ? "b" : "a"); o = d "/objdump.txt"; addr = 4096; row = 0
        printf "0000000000001000 <big_k(::T[True, DType.int32])>:\n" > o
        for (i = 0; i < n; i++) {
            if (s && i % 50 == 25) continue                          # B drops every 50th row
            t = (s && i == 3000) ? "sub eax, 3000" : "add eax, " i   # and rewrites row 3000
            if (i == 5000) printf " %x:\tjmp\t0x1000 <big_k(%s)+0x10>\n", addr, sym > o
            else printf " %x:\t%s\n", addr, t > o
            at[s, i] = addr; addr += 4; row++
        }
        printf "cycles\tbig\t%x\t%d\n", at[s, 100], s ? 6000 : 5000 > d "/samples.tsv"
        printf "cycles\tbig\t%x\t%d\n", at[s, 3000], 7000 > d "/samples.tsv"
        printf "cycles\t100\n" > d "/stat.tsv"
    }
}'
big_kb=$(stat -c %s .work/big/a/objdump.txt)
[ "$big_kb" -gt 1400000 ] || fail diff "the big objdump is only $big_kb bytes"
/usr/bin/time -f "%e %M" -o .work/big/time.txt ./build/corewait-an diff .work/big/a .work/big/b --top 10 > .work/big/diff.txt || fail diff "a 7000 x 7000 row function was refused: $(head -1 .work/big/diff.txt)"
read -r secs kb < .work/big/time.txt
grep -q "^diff: cycles 12000 -> 13000 (+8.3%), rows changed 3$" .work/big/diff.txt || fail diff "big diff header: $(head -1 .work/big/diff.txt)"
[ "$(gawk 'NR > 2 && NF >= 5 { t += $5 } END { print t }' .work/big/diff.txt)" = 1000 ] || fail diff "the changed rows do not sum to +1000: +1000 (row 100), -7000 (A row 3000 gone), +7000 (B's rewritten row)"
CW_ALIGN_CELLS=1000000000 ./build/corewait-an diff .work/big/a .work/big/b --top 10 > .work/big/diff-table.txt
cmp -s .work/big/diff.txt .work/big/diff-table.txt || fail diff "the linear-memory alignment differs from the table on a pair with a unique LCS"
gawk -v s="$secs" -v kb="$kb" 'BEGIN { exit !(kb < 512000) }' || fail diff "peak RSS $((kb / 1024)) MB over 500 MB"
echo "ok 11 diff: 7000 x 7000 rows aligned in $secs s and $((kb / 1024)) MB with 1.4 MB symbol lines, cycles conserved, equals the table"
# the forced linear-memory alignment gives the table's cycles, row count and header on the frozen pairs
for pair in "desktop-chase laptop-chase" "desktop-chase desktop-chase" "dupname/a dupname/b"; do
    set -- $pair
    CW_ALIGN_CELLS=1000000000 ./corewait diff fixtures/$1 fixtures/$2 --top 12 > .work/h-t.txt
    CW_ALIGN_CELLS=0 ./corewait diff fixtures/$1 fixtures/$2 --top 12 > .work/h-h.txt
    cmp -s .work/h-t.txt .work/h-h.txt || fail diff "forced linear-memory alignment differs from the table on $1 vs $2: $(diff .work/h-t.txt .work/h-h.txt | head -3)"
done
echo "ok 11b diff: forced linear-memory alignment equals the table on the frozen pairs"
# 12. bad input: exits 1 naming step and line; CRLF and uppercase/0x hex parse like the fixture; a new row diffs as "new"
bad() {  # bad STEP WANT CMD...: CMD must exit 1 and print "FAIL STEP: ...WANT"
    local step=$1 want=$2; shift 2
    if "$@" > .work/bad.txt 2>&1; then fail bad-input "$step accepted: $*"; fi
    grep -q "^FAIL $step: .*$want" .work/bad.txt || fail bad-input "$step message: $(head -1 .work/bad.txt)"
}
printf 'chase_k mem 12.\n' > .work/b1.txt; printf '# x\nchase_k mem abc\n' > .work/b2.txt
bad budget "b1.txt:1" ./corewait budget fixtures/desktop-chase .work/b1.txt
bad budget "b2.txt:2" ./corewait budget fixtures/desktop-chase .work/b2.txt
for v in addr count crlf hex; do rm -rf .work/in-$v; cp -r fixtures/desktop-chase .work/in-$v; done
sed -i '2s/\t1347\t/\tzz12\t/' .work/in-addr/samples.tsv
sed -i '3s/\t[0-9]*$/\t-5/' .work/in-count/samples.tsv
bad samples "line 2" ./corewait show .work/in-addr --top 12
bad samples "line 3" ./corewait show .work/in-count --top 12
for f in objdump.txt samples.tsv stat.tsv; do rm -rf .work/in-miss; cp -r fixtures/desktop-chase .work/in-miss; rm .work/in-miss/$f
    bad input "no $f" ./corewait show .work/in-miss --top 12; bad input "no $f" ./corewait diff fixtures/desktop-chase .work/in-miss; done
sed -i 's/$/\r/' .work/in-crlf/samples.tsv
gawk -F'\t' -v OFS='\t' '{ $3 = "0x" toupper($3) } 1' fixtures/desktop-chase/samples.tsv > .work/in-hex/samples.tsv
for v in crlf hex; do
    ./corewait show .work/in-$v --top 12 > .work/in-$v.txt || fail bad-input "$v samples refused: $(head -1 .work/in-$v.txt)"
    cmp -s .work/in-$v.txt fixtures/golden/desktop-chase.txt || fail bad-input "$v samples change the table"
done
rm -rf .work/in-empty; cp -r fixtures/desktop-chase .work/in-empty; : > .work/in-empty/samples.tsv
./corewait diff .work/in-empty fixtures/desktop-chase --top 12 > .work/new.txt 2>&1 || fail diff "empty A refused: $(head -1 .work/new.txt)"
grep -q "^diff: cycles 0 -> [0-9]* (new)" .work/new.txt || fail diff "0-cycle base header: $(head -1 .work/new.txt)"
d=.work/bad-short; mkdir -p $d; cp fixtures/idiom/rmw/{objdump.txt,stat.tsv} $d/
printf 'cycles\tp\t1004\t100\n\ncycles\tp\t1008\t100\n' > $d/samples.tsv
grep -q "^total *200" <(./corewait show $d --causes) || fail bad "a blank samples line dropped the next line"
printf 'cycles\tp\n' > $d/samples.tsv
./corewait show $d > .work/bad-short.txt 2>&1 && fail bad "a 2-field samples line passed"
grep -q "FAIL samples: too few fields at .* line 1" .work/bad-short.txt || fail bad "short samples line: $(cat .work/bad-short.txt)"
./corewait show fixtures/idiom/rmw --top > .work/bad-opt.txt 2>&1 && fail bad "--top with no value passed"
grep -q "FAIL usage: --top needs a value" .work/bad-opt.txt || fail bad "--top with no value: $(head -2 .work/bad-opt.txt)"
for b in 'k mem' '' '# only a comment'; do printf '%s\n' "$b" > .work/bad-budget.txt
    ./corewait budget fixtures/idiom/rmw .work/bad-budget.txt > /dev/null 2>&1 && fail bad "budget '$b' passed as a gate"; done
echo "ok 12 bad input: budget and samples fail with the line, a missing input file fails, CRLF and 0x/uppercase hex parse, a 0-cycle base diffs as new"
# 13. register and memory roles: a zero idiom and cmn read/write nothing, vextract/setcc to memory store, not load
./corewait show fixtures/idiom/zero --top 5 > .work/idiom-zero.txt
[ "$(grep -c ' busy ' .work/idiom-zero.txt)" = 2 ] || fail idiom "xor/vpxor zero idiom not busy: $(grep ' dep ' .work/idiom-zero.txt)"
./corewait show fixtures/idiom/store --top 5 > .work/idiom-store.txt
grep -q "busy *add x1, x0, x2" .work/idiom-store.txt || fail idiom "a row after cmn is dep: cmn writes no register"
grep -q "^ *101c .* mem *ret" .work/idiom-store.txt || fail idiom "mem skid went to a store (setne to memory): $(grep ' mem ' .work/idiom-store.txt)"
./corewait show fixtures/idiom/rmw --top 5 > .work/idiom-rmw.txt
[ "$(grep -c ' dep ' .work/idiom-rmw.txt)" = 2 ] || fail idiom "x86 add/inc after imul not dep: they read their destination"
./corewait show fixtures/idiom/neon --top 5 > .work/idiom-neon.txt
[ "$(grep -c ' dep ' .work/idiom-neon.txt)" = 2 ] || fail idiom "fmla v0.4s chain not dep: the arrangement suffix hid the register"
./corewait show fixtures/idiom/cvt --top 5 > .work/idiom-cvt.txt
grep -q "^ *1004 .* mem *nop" .work/idiom-cvt.txt || fail idiom "mem skid went to a vcvtps2ph store"
echo "ok 13 roles: zero idiom and cmn are no dependence, a store to memory takes no load skid"
# 14. diff aligns on the instruction shape: b is a with rcx -> r11 and edx -> r9d in every row, the same cycles
./corewait diff fixtures/rename/a fixtures/rename/b > .work/rename.txt
head -1 .work/rename.txt | grep -q "rows changed 0$" || fail diff "renamed registers diff as changed rows: $(head -1 .work/rename.txt)"
echo "ok 14 diff: a build with other registers aligns row for row"
echo "ALL OK"
