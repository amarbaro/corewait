# corewait devices

`corewait bw DEV` = sequential read GB/s: N `cwprobe stream` processes released together, each on its own buffer, summed.
The buffer is `--n` MB per process (desktop 256, others 64). "1t" on a phone is pinned like `record` pins (the first cpu
mask `taskset` accepts), so it is the same core the stream probe ran on; 2t and up are unpinned. `show --bw` takes the
column that matches the question (a single-threaded kernel: 1t; a threaded one: all).

| device | cpu | 1t | 2t | 4t | all threads | measured | pinned core (1t) |
|---|---|---|---|---|---|---|---|
| desktop | 7800X3D, Zen 4, DDR5, 16 threads | 49.3 | 54.8 | 54.2 | 55.5 | 2026-10-21 | none |
| laptop | i5-6200U, Skylake, 4 threads | 16.5 | 23.8 | 27.0 | 27.5 | 2026-10-21 | none |
| flip | Z Flip4, X2/A710/A510, 6 usable cpus | 13.0 | 41.1 | 44.2 | 46.9 | 2026-10-21 | cpu 5 (A710): cpu 7 and 6 were isolated |
| xiaomi | 17 Ultra, Oryon, 8 cpus | 72.5 | 70.8 | 69.3 | 66.6 | 2026-10-21 | none |
| oneplus | A76 | PENDING | | | | device absent | |

- Xiaomi: the numbers were measured before the phone dropped off wifi (adb offline, 2026-10-21 23:30). Its fixtures keep
  the stat.tsv without `time_us` (no `--bytes` on them), and the re-record plus a fresh bw are **PENDING (device
  offline)**, not failed. `check-live.sh xiaomi` prints PENDING and exits 0 while it is not attached; `CW_XIAOMI_ADB=ip:port`
  points the device table at the new wireless-debugging port.
- Desktop 1t varied from 46.0 to 57.7 over five runs (load average 3-20 from other sessions); the table keeps the first run (49.3),
  which `check.sh` step 7 reads. Laptop 1t: 15.9 to 16.5; flip 1t 11.5 to 13.0 depending on which core taskset accepted.
- Aggregate bandwidth falls slightly past one process on the desktop-class phone (Oryon one core streams 70 GB/s, near the
  memory limit) and on the desktop it saturates at 55 GB/s (7800X3D, two DDR5 channels, fabric limit).
- The stream probe's own GB/s while profiled (`fixtures/*-stream/run.txt`) agrees with 1t within 30%: desktop 42.9 vs
  49.3, laptop 15.1 vs 16.5, flip 12.6 vs 13.0, xiaomi 68.5 vs 72.5 (`check-live.sh`).
- Counters: see the table below; a Skylake `perf` run multiplexes the 7 stat events (perf scales them), the
  Zen 4 summary uses the PipelineL1 events over 6 slots per cycle, ARM over cycles.

## Counters per device (measured 2026-10-21, user-space counters, no root)

| device | name | how | profiler | per-process counters that work |
|---|---|---|---|---|
| desktop 7800X3D (Zen 4, AVX-512) | desktop | local | `perf` (paranoid 2: use `:u` events) | cycles, instructions, cache-misses; Zen 4 `ex_ret_*`, `de_dis_*`, `ls_*`. No generic stalled-cycles. |
| laptop i5-6200U (Skylake, AVX2) | laptop | ssh `$CW_LAPTOP_SSH` | `perf` 7.2.6  | cycles, instructions, `topdown-fetch-bubbles`, `-recovery-bubbles`, `-slots-issued` |
| Xiaomi 17 Ultra (Oryon, SVE2, SME) | xiaomi | adb `$CW_XIAOMI_ADB` (wifi) | `/system/bin/simpleperf` | cpu-cycles, instructions, raw-stall-backend, raw-stall-frontend, raw-stall-backend-mem, raw-l1d-cache-refill, raw-l2d-cache-refill (all `:u`) |
| Galaxy Z Flip4 (X2/A710/A510) | flip | adb `$CW_FLIP_ADB` | `/system/bin/simpleperf` | the same set as Xiaomi |
| OnePlus (A76) | oneplus | adb `$CW_ONEPLUS_ADB` | simpleperf | assume the same set; check when attached |

`simpleperf stat -a` and kernel samples need root: always profile a command you start (`-- cmd`), with `:u` events.
`simpleperf record -e cpu-cycles:u -- cmd` works on both phones (133 / 61 samples on `dd`).

Remote targets come from `CW_*` variables or `~/.config/corewait/devices.env` (see the top of `corewait`).
The phone lock lives in `$CW_LOCK_DIR` (default `~/.cache/corewait`); point it at a shared folder when other tools drive the same phone.
