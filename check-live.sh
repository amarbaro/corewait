#!/usr/bin/env bash
# Live gate for one device: record the four probes and check each one's top cause, and that bw agrees with stream.
#   chase mem · stream mem (bw 1t within 30% of the stream probe's GB/s) · fmachain dep · branchy branch (busy when the
#   device has no mispredict event, said in the output). Writes .work/live-DEV.txt; timings are not gated.
# Usage: ./check-live.sh desktop|laptop|xiaomi|flip|oneplus [freeze]      freeze copies the recordings to fixtures/DEV-PROBE
set -euo pipefail
cd "$(dirname "$0")"
dev=${1:?usage: ./check-live.sh desktop|laptop|xiaomi|flip|oneplus [freeze]}
fail() { echo "FAIL $1: $2"; exit 1; }
declare -A want=([chase]=mem [stream]=mem [fmachain]=dep [branchy]=branch)

live() {
    local p out got ach bw1
    [ build/cwprobe-"$dev" -nt probes/cwprobe.mojo ] && [ build/cwprobe-"$dev" -nt probes/kgen_shim.c ] || ./corewait build "$dev"
    for p in chase stream fmachain branchy; do
        out=.work/live-$dev/$p; rm -rf "$out"
        ./corewait record "$dev" "$out" -- build/cwprobe-"$dev" "$p"
        ./corewait show "$out" --fn "${p}_k" --causes | tee "$out/causes.txt"
        got=$(gawk '$1 ~ /^(mem|fe|dep|branch|busy)$/ && $2 + 0 > best { best = $2 + 0; got = $1 } END { print got }' "$out/causes.txt")
        if [ "$p" = branchy ] && ! grep -q '^p_br	' "$out/stat.tsv" && [ "$got" = busy ]; then
            echo "note: $dev has no mispredict event, busy accepted for branchy"; got=branch
        fi
        [ "$got" = "${want[$p]}" ] || fail "$p" "top cause of ${p}_k is $got, want ${want[$p]} ($out/causes.txt)"
        echo "ok $dev $p: ${p}_k top cause $got"
        if [ "${2:-}" = freeze ]; then rm -rf "fixtures/$dev-$p"; mkdir -p "fixtures/$dev-$p"; cp "$out"/{samples.tsv,stat.tsv,objdump.txt,meta.txt,run.txt} "fixtures/$dev-$p/"; fi
    done
    ach=$(gawk '/GBps/ { print $NF }' .work/live-"$dev"/stream/run.txt | tail -1)
    bw1=$(./corewait bw "$dev" | tee /dev/stderr | gawk '{ for (i = 1; i <= NF; i++) if ($i ~ /^1t=/) { sub(/1t=/, "", $i); print $i } }')
    gawk -v a="$ach" -v b="$bw1" 'BEGIN { exit !(a > 0 && b > 0 && b / a >= 0.7 && b / a <= 1.3) }' || fail bw "bw 1t $bw1 GB/s vs stream probe $ach GB/s differ by more than 30%"
    echo "ok $dev bw: 1t $bw1 GB/s within 30% of the stream probe's $ach GB/s"
    echo "LIVE OK $dev"
}

mkdir -p .work
./corewait attached "$dev" || { echo "PENDING $dev: not attached, nothing checked"; exit 0; }
live "$@" 2>&1 | tee ".work/live-$dev.txt"
exit "${PIPESTATUS[0]}"
