# corewait

Per-instruction CPU stall profiler for desktop, laptop and phones: hardware-counter samples joined to the disassembly,
with a cause on every row. Devices and counters: `docs/DEVICES.md`.

```
corewait build DEV                            build/cwprobe-DEV: the probe cross-compiled for the device (no Mojo runtime on it)
corewait record DEV OUT [--dso LIB|auto] [--no-stat] [--pid PID] -- [K=V ...] BINARY [ARGS...]   samples.tsv + stat.tsv + objdump.txt + meta.txt in OUT
                                              --dso: report one loaded library of a host process such as python (auto, or a script BINARY: the one with the most cycles);
                                              dsos.tsv ranks all of them. --no-stat: no second run. --pid: sample a running server for as long as BINARY (`sleep 60`) runs
corewait pick OUT LIB|auto                    report another library of OUT/perf.data without a new run
corewait show OUT [--top N] [--causes] [--fn SYMBOL] [--k K] [--bytes B --bw GBPS]
                                              one row per instruction: cycles, mem/fe/br events, cause, text;
                                              --bytes/--bw add a speed-of-light line: achieved GB/s over the device bw (docs/DEVICES.md)
corewait diff OUT_A OUT_B [--top N]           per-row cycle delta, rows of same-named functions aligned by LCS on the text with register names masked, any size
                                              (O(nm) table up to 40M cells, then Hirschberg: memory linear in the rows; CW_ALIGN_CELLS moves the switch)
corewait budget OUT FILE                      FILE lines "fn cause max-percent"; exit 1 on a breach (a CI gate for kernels)
corewait merge OUT DIR...                     add repeated recordings of one binary (CW_DIV=20 shortens the sampling periods for a 40 ms kernel)
corewait stat DEV OUT                         OUT/stat.tsv again from OUT/stat.raw (an event the CPU did not count is left out)
corewait bw DEV                               sequential-read GB/s with 1, 2, 4 and all concurrent stream probes
probes/cwprobe.mojo                           chase | stream | fmachain | branchy, ~0.5 s each, one dominant cause
check.sh                                      CPU-only gate: build, record smoke, golden fixtures, mutant, 1M-row speed, bad input, register roles
check-live.sh DEV [freeze]                    records the four probes on a device, checks each top cause and bw vs stream
```

Devices (`desktop laptop xiaomi flip oneplus`) are one table at the top of `corewait`. A phone is locked through
`$CW_LOCK_DIR/phone-SERIAL.lock` (default `~/.cache/corewait`), taken by `record` and `bw`; the laptop is used only in
`~/corewait`. `fixtures/DEV-PROBE/` holds committed recordings and `fixtures/golden/` the frozen tables (`FREEZE=1
./check.sh` rewrites them, `./check-live.sh DEV freeze` re-records a device).

ComfyUI or any Python job: `corewait record desktop OUT --no-stat -- .venv/bin/python job.py`, or `--pid SERVER -- sleep 60` while a
prompt runs. Under `gpu-wait` pass flags, not env: `gpu-wait run --room cpu -- corewait ...`. Read `dsos.tsv` first. A BLAS or OpenMP pool
spins while idle and tops it with no real work (one spin loop of `blas_thread_server` held 30 % of a cKDTree run): set
`OPENBLAS_NUM_THREADS=1` or `OMP_WAIT_POLICY=passive` as K=V, or `pick` the library you care about. libtorch_cpu.so (440 MB) adds 50 s of disassembly.

How a row gets its cause (`src/corewait.mojo`, header): a sample lands a few instructions after what stalled, so the
cycles and memory (branch-miss) events of a row go to the nearest preceding load (branch), up to K rows back (`--k 0`
turns that off). Then, first match: `mem`, `branch`, `dep`, `fe`, `busy`. An event counts for a row only with 10 samples
of it and at least half as large a share of the event as of the cycles. `dep` is a non-load row that reads its own destination: a source
named like the destination (`fmla v0.4s, v0.4s, v3.4s`), or an x86 two-operand form (`add rax, rcx`, `inc rax`, `vfmadd231`); a zero idiom
(`xor eax, eax`) is not. The `run:` line comes from the whole-run
`stat.tsv`, not from the samples.

An `objdump.txt` is read in 8 MB chunks and an instruction line is cut to 4096 bytes: llvm-objdump prints a branch target's whole
mangled symbol, so a Mojo kernel's file holds 1.4 MB lines (the kinestride `smooth` recording: 1.1 GB, 14,601 lines). `diff` of two
of them: 4.5 s and 59 MB, was 36 s and 5.7 GB and then a refusal.
