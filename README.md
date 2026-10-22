# corewait

Per-instruction CPU stall profiler for desktop, laptop and phones: hardware-counter samples joined to the disassembly,
with a cause on every row. Devices and counters: `docs/DEVICES.md`.

```
corewait build DEV                            build/cwprobe-DEV: the probe cross-compiled for the device (no Mojo runtime on it)
corewait record DEV OUT -- BINARY [ARGS...]   samples.tsv + stat.tsv + objdump.txt + meta.txt in OUT
corewait show OUT [--top N] [--causes] [--fn SYMBOL] [--k K] [--bytes B --bw GBPS]
                                              one row per instruction: cycles, mem/fe/br events, cause, text;
                                              --bytes/--bw add a speed-of-light line: achieved GB/s over the device bw (docs/DEVICES.md)
corewait diff OUT_A OUT_B [--top N]           per-row cycle delta, rows of same-named functions aligned by LCS on the text
corewait budget OUT FILE                      FILE lines "fn cause max-percent"; exit 1 on a breach (a CI gate for kernels)
corewait merge OUT DIR...                     add repeated recordings of one binary (CW_DIV=20 shortens the sampling periods for a 40 ms kernel)
corewait bw DEV                               sequential-read GB/s with 1, 2, 4 and all concurrent stream probes
probes/cwprobe.mojo                           chase | stream | fmachain | branchy, ~0.5 s each, one dominant cause
check.sh                                      CPU-only gate: build, record smoke, golden fixtures, mutant, 1M-row speed
check-live.sh DEV [freeze]                    records the four probes on a device, checks each top cause and bw vs stream
```

Devices (`desktop laptop xiaomi flip oneplus`) are one table at the top of `corewait`. A phone is locked through
`$CW_LOCK_DIR/phone-SERIAL.lock` (default `~/.cache/corewait`), taken by `record` and `bw`; the laptop is used only in
`~/corewait`. `fixtures/DEV-PROBE/` holds committed recordings and `fixtures/golden/` the frozen tables (`FREEZE=1
./check.sh` rewrites them, `./check-live.sh DEV freeze` re-records a device).

How a row gets its cause (`src/corewait.mojo`, header): a sample lands a few instructions after what stalled, so the
cycles and memory (branch-miss) events of a row go to the nearest preceding load (branch), up to K rows back (`--k 0`
turns that off). Then, first match: `mem`, `branch`, `dep`, `fe`, `busy`. An event counts for a row only with 10 samples
of it and at least half as large a share of the event as of the cycles. The `run:` line comes from the whole-run
`stat.tsv`, not from the samples.
