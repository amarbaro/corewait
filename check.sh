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
echo "ok 5 diff: self is zero, cross-device chase load aligned, frozen"

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
echo "ALL OK"
