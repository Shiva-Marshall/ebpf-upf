# Per-Packet Datapath Cost (supersedes the wire-level throughput sweep)

## Why this measurement replaced the earlier one

The earlier wire-level throughput harness (`native_throughput.py` +
`xdp_throughput_blast.c`) measured a **closed loop on a single host**:

    generator (enp24s0f1, cores 16-23)
        -> physical cable ->
    enp24s0f0 RX: XDP + TC ingress
        -> FAR redirect, out_ifindex = enp24s0f0 ->
    enp24s0f0 TX (back toward enp24s0f1)

Every received packet therefore creates transmit work on the same NIC, and
the generator threads, the receive softirqs and the redirect-transmit work
all compete for the same 24 cores. The system settles wherever scheduling
happens to put it. Directly observed: two identical 8-thread, 5-second runs
offered 14,399,894 and 2,987,392 packets respectively -- a 4.8x difference
in offered load between runs of the same command.

NIC counters confirmed the loop rather than a sender fault:
  - enp24s0f1 tx_packets delta == generator's own sent count exactly
    (the sender transmits everything it claims)
  - enp24s0f0 tx_packets delta ~= its rx_packets delta
    (i.e. the UPF re-transmits essentially every packet it receives)

That equilibrium is a property of the test rig, not of the UPF datapath, so
it is not a sound basis for a throughput claim and the earlier table has
been withdrawn.

A second defect was found in the same harness: receive-side CPU utilisation
was attributed by diffing `/proc/interrupts` for the NIC's IRQ lines and
averaging `mpstat` over the CPUs whose counts rose. Under sustained load
NAPI stops re-arming interrupts and stays in polling mode, so the interrupt
count barely moves while the core is saturated in softirq -- the attribution
silently misses the busy core. This produced an impossible figure: 14% of a
core while forwarding 0.914 Mpps, when the programmes alone cost 235 ns per
packet (= 21% of a core at that rate before any driver or skb work).

## What is measured instead

Per-packet cost of each eBPF programme, from the kernel's own per-programme
accounting (`kernel.bpf_stats_enabled`), on **real wire traffic**. Per-packet
cost is invariant to how many packets flow, so the closed-loop instability
above does not affect it. Harness: `test/bench_prog_cost.sh`.

`BPF_PROG_TEST_RUN` was tried first and rejected: for SCHED_CLS programmes
the kernel's test-run path calls `eth_type_trans()`, consuming the Ethernet
header, so the TC programmes exited at their first parse check without
executing the path under test. This was caught by checking the per-stage
counters -- they failed to advance -- rather than by trusting the timing
number, which would have reported a spurious ~8 ns for TC ingress.

## Result (10 rounds, 200 kpps x 5 s per round)

| Programme | median ns/pkt | min | max | spread |
|---|---|---|---|---|
| XDP uplink classification | 101.7 | 101.5 | 101.8 | 0.3% |
| TC ingress (PDR/FAR + QER + URR + decap) | 133.4 | 132.5 | 134.9 | 1.8% |
| TC egress (downlink GTP-U encap) | 48.5 | 48.4 | 48.7 | 0.6% |

    uplink path (XDP + TC ingress) = 235.1 ns/packet -> 4.25 Mpps per core
    incl. TC egress                = 283.6 ns/packet -> 3.53 Mpps per core

## Cross-validation (three independent methods)

The TC-ingress figure is corroborated by two measurements taken by different
means, in different sessions, for different purposes:

| Method | TC ingress |
|---|---|
| `bpf_stats`, QER contention experiment (1 queue, per-CPU bucket) | 130.1 ns |
| `bpf_stats`, this measurement | 133.4 ns |
| In-pipeline `bpf_ktime_get_ns()` bracket, 249,998 samples | 140.7 ns |

The bracket figure is expected to sit slightly higher: it includes the cost
of its own two timestamp reads. Agreement within ~8% across three unrelated
methods.

## Scope (stated so the figure is not over-read)

This is the cost of the eBPF programmes themselves. It excludes driver
receive, DMA, `sk_buff` allocation, and wire time. The derived per-core
packet rate is therefore an upper bound on what the datapath logic permits,
not a prediction of achievable line rate on a given NIC. It is reported as a
cost measurement with a derived bound, not as an end-to-end throughput
result.
