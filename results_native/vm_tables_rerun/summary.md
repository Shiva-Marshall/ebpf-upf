# Tables 5, 6, 7 Re-Run on Native-XDP Hardware

Re-runs the three timing tables (rule-update, zero-downtime, contention-sweep)
originally measured only on the VM/generic-XDP testbed, on the bare-metal
native-XDP testbed (Intel XXV710/i40e, physical loop enp24s0f1->enp24s0f0),
using the identical scripts/parameters where the underlying binaries are
testbed-agnostic (bench_rule_update.c operates on pinned maps directly) and
native-specific driver scripts otherwise (zero_downtime_native.sh,
contention_sweep_native.sh -- same logic as the originals, traffic routed
over the physical loop instead of a veth pair inside a netns).

## Table 5 equivalent: rule-update latency, no concurrent traffic
See ruleupdate_native_n*.csv and the run transcript; N in {1,10,50,100,500,1000,2000}.

## Table 6 equivalent: zero-downtime, 100 rules mid-stream
See zerodowntime_native_summary.txt: 499,998 packets sent at 50,000 pps target,
zero loss, zero misses, per-rule mean 4.136us (100-rule batch).

## Table 7 equivalent: contention sweep, R=5, 4 rates x 3 batch sizes
Total measurements: 60
Total G-PDU packets across all cells: 14399894
Total misclassified/missed packets: 0
Max p99 across all 60 cells: 9.504 us (vs 14 us bound on the VM testbed)

Zero packets were mis-classified or dropped in any of the 60 cells, confirming
the zero-loss property holds on native hardware as well as the original
VM/generic-XDP testbed, at a lower worst-case p99 (9.5us vs 14us) despite
roughly 9x more packets traversing the data plane during the measurement
windows (14.4M vs 1.58M), since native-XDP sustains the target send rates
exactly where the VM/veth generator could not.
