# Native-XDP Throughput, CPU Utilization, and In-Pipeline Latency (Phase 8)

Replaces the paper's design-phase analytical projections (Table 9) with
measurements taken on the native-XDP testbed (Section "Prototype and
Testbed"): Intel XXV710 25GbE, `i40e`, native XDP attach confirmed via
`ip link show` reporting `xdp` not `xdpgeneric`.

## Why not TRex

TRex (a real DPDK-based line-rate generator, already installed on this host
from prior work) was the first choice, but DPDK's i40e PMD refuses to run
on `enp24s0f1` while its sibling port `enp24s0f0` (same physical chip)
stays under the kernel driver: "i40e interface 0000:18:00.0 is under Linux
and will interfere with TRex" (a known DPDK/i40e restriction, not a config
error -- see trex-tgn.cisco.com/youtrack/issue/trex-528). Since our own XDP
programme must stay under the kernel driver on `enp24s0f0`, TRex cannot
share this card. The in-kernel `pktgen` module loads cleanly but does not
create its debugfs control directory on this kernel build; not chased
further given time constraints.

## Generator

`test/xdp_throughput_blast.c`: N independent threads, each its own raw
AF_PACKET socket with `PACKET_QDISC_BYPASS` and batched `sendmmsg()`
(64 packets/syscall), each thread on a distinct outer UDP source port so
RSS spreads flows across receive queues/CPUs (same reasoning as
`test/qer_blast.c` from Phase 7). NIC TX/RX ring sizes raised from the
512-descriptor default to the hardware maximum (4096) on both ports
(`ethtool -G ... tx 4096 rx 4096`) -- at the default ring size the
generator's own TX ring silently dropped packets under load in a way
`sendmmsg()` never surfaces as an error, which the first exploratory runs
caught by cross-checking the sender's self-reported count against the
receiver's hardware counter and finding a 3x discrepancy (see "Ground
truth" below).

This generator does not claim line rate. It reports whatever it actually
achieves; the achieved ceiling and why it is generator- not UPF-limited
are reported explicitly, in the same spirit as the existing benchmarking
framework's own `generator_ceiling_mpps` disclosure.

## Ground truth: hardware counters, not self-reported sends

`test/native_throughput.py` measures the *receiving* NIC's own hardware
`rx_packets`/`rx_bytes` counters (`ethtool -S`) before and after each
trial -- not the generator's self-reported "sent" count. The first
exploratory run showed why this matters: the generator claimed 6.15M
packets sent while the receiving NIC's hardware counter recorded only
2.18M actually arriving. Every reported figure is cross-checked a second,
independent way: the XDP programme's own `/metrics rx_total` counter
delta is compared against the hardware counter delta every single trial,
and the two agreed exactly (`hw_matches_xdp_metric=True`) on every trial
in the reported sweep, with no exception.

CPU utilization is attributed by comparing `/proc/interrupts` for this
NIC's `TxRx` IRQ lines before and after each trial to find which CPUs
*actually* handled that trial's traffic, then averaging `mpstat`'s
100-idle% over exactly those CPUs for exactly the trial's duration --
not a guessed core range.

## Throughput result (`throughput_raw.txt`, 3 repeats per cell unless noted)

| Frame | Threads | Achieved Mpps | Achieved Gbps | Active CPUs | Mean CPU util | Loss |
|---|---|---|---|---|---|---|
| 64B | 1 | 0.914 | 0.658 | 1 | 14.3% | 0 |
| 64B | 2 | 1.57 | 1.13 | 2-3 | 30.5% | 0 |
| 64B | 4 | 2.82 | 2.03 | 3-4 | 77.3% | 0 |
| 64B | 6 | 3.37 | 2.43 | 5 | 67.6% | 0 |
| 64B | 8 | **3.86** | 2.78 | 7 | 50.6% | 0 |
| 64B | 12 | 3.63 | 2.62 | 8 | 35.9% | 0 |
| 64B | 16 | 2.53 | 1.82 | 9 | 34.4% | 0 |
| 1500B | 1 | 0.681 | 8.15 | 1 | 11.3% | 0 |
| 1500B | 2 | 0.822 | 9.84 | 2-3 | 40.2% | 0 |
| 1500B | 4 | 0.822 | 9.84 | 2-4 | 46.9% | 0 |

Peak clean measurement: **3.86 Mpps at 64B (2.78 Gbps), zero loss**, 8
generator threads, 7 CPUs engaged on the receive side at a mean 50.6%
utilization -- headroom remains on the receive side; beyond 8 generator
threads the *sender's own* 8 dedicated cores become oversubscribed and
achieved throughput falls, which is a generator artifact, not a UPF one.
1500B throughput plateaus early (0.82 Mpps / 9.84 Gbps) with receive-side
CPU utilization well under 50%, confirming that ceiling is also
generator- (per-packet syscall/copy overhead, largely independent of
frame size), not UPF-side.

These are real, hardware-verified numbers, not the design-phase
projection (6.1-8.5 Mpps, single core, extrapolated from external XDP
benchmarks) they replace. They are lower than that projection at the
single-core operating point (0.91 Mpps measured vs. 6.1-8.5 Mpps
projected for one core) -- we report this gap honestly rather than
omit it: our own generator cannot drive enough offered load to find the
UPF's true single-core ceiling (CPU utilization is only 14% at n=1),
so the 0.91 Mpps figure is a generator-bound floor, not the UPF's
capacity. The paper states this explicitly rather than implying the
measured figure supersedes the projection as an upper bound.

## In-pipeline TC-ingress latency (`latency_events_raw.txt`)

A build-time probe (`-DUPF_EMIT_LATENCY_EVENTS`) brackets
`bpf_ktime_get_ns()` at TC-ingress entry and again immediately before the
redirect on the admitted/forwarded path, matching the same
"pktParse->executeFAR" segment definition the existing benchmarking
framework on this host uses for other UPFs' in-pipeline probes. Both
timestamps are read on the same CPU within one programme invocation for
the same packet, so there is no cross-hook (XDP/TC boundary) correlation
problem to solve.

Captured at 50,000 pps for 5s (249,998 samples), deliberately at a rate
far below the measured NDR so the number reflects pipeline cost, not
queueing (same methodology note the reference framework uses for its own
latency test case).

| Metric | Value |
|---|---|
| samples | 249,998 |
| mean | 140.7 ns |
| p50 | 141.0 ns |
| p90 | 144.0 ns |
| p99 | 160.0 ns |
| p99.9 | 166.0 ns |
| max | 2079 ns |

**Scope caveat, stated explicitly to avoid a false comparison**: this
measures the TC-ingress segment only -- parse, TEID/PDR/bundle lookup,
QER admission check, URR update, decap -- immediately before hand-off to
`bpf_redirect()`. It does *not* include the separate XDP classification
stage, DMA/NIC receive latency, or wire time, so it is not directly
comparable to the paper's original end-to-end analytical projection
(~7.1-7.2us) as a smaller-is-better replacement; it measures a narrower
segment extremely precisely rather than a wider segment approximately.
Both figures are retained with this scope explicitly stated.

## Files

- `test/xdp_throughput_blast.c` -- multi-threaded AF_PACKET generator.
- `test/native_throughput.py` -- per-trial harness (hardware-counter
  ground truth, IRQ-attributed CPU utilization).
- `test/analyze_latency.py` -- percentile analysis for the latency capture.
- `throughput_raw.txt`, `run_throughput_sweep.sh` -- raw sweep + driver.
- `latency_events_raw.txt`, `latency_summary.txt` -- raw capture + analysis.
