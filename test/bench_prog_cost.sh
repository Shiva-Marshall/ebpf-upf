#!/usr/bin/env bash
# bench_prog_cost.sh -- per-packet cost of each datapath programme, measured
# with the kernel's own per-programme accounting (kernel.bpf_stats_enabled),
# on real wire traffic.
#
# Why this rather than the wire-level throughput harness: that harness
# measures a closed loop on one host (generator on enp24s0f1 -> enp24s0f0
# receives -> FAR redirects back out enp24s0f0), so offered load, receive
# softirq and redirect-transmit work all compete for the same cores and the
# system settles wherever scheduling puts it -- two identical runs were
# observed to offer 14.2M and 3.0M packets. Per-packet *cost*, by contrast,
# is invariant to how many packets flow, so it is reproducible and is a
# property of the datapath rather than of the test rig.
#
# Why this rather than BPF_PROG_TEST_RUN: the test-run path builds a
# synthetic skb whose layout differs per programme type (for SCHED_CLS the
# kernel calls eth_type_trans(), consuming L2), which made the TC programmes
# exit at their first parse check without executing the path under test --
# confirmed by the per-stage counters failing to advance. Measuring on real
# traffic avoids that entirely, and the counters confirm the real path runs.
#
# Method: clear counters, enable bpf_stats, push a fixed amount of real
# GTP-U traffic, read run_time_ns/run_cnt per programme, disable stats.
# Reported per round so run-to-run spread is visible rather than hidden.
#
# Usage: sudo bash test/bench_prog_cost.sh [rounds] [pps] [duration_s]
set -euo pipefail
cd "$(dirname "$0")/.."

ROUNDS=${1:-5}
PPS=${2:-200000}
DUR=${3:-5}
GEN_IFACE=${GEN_IFACE:-enp24s0f1}
TEID=${TEID:-0x9000}

PINS=(xdp_prog/xdp tc_prog/classifier tc_egress_prog/classifier)
NAMES=(xdp_uplink tc_ingress tc_egress)

stat_of() {  # $1 = pin path -> "run_time_ns run_cnt"
    bpftool -j prog show pinned "/sys/fs/bpf/upf/$1" \
      | python3 -c 'import json,sys; d=json.load(sys.stdin); d=d[0] if isinstance(d,list) else d; print(d.get("run_time_ns",0), d.get("run_cnt",0))'
}

sysctl -w kernel.bpf_stats_enabled=1 >/dev/null
trap 'sysctl -w kernel.bpf_stats_enabled=0 >/dev/null' EXIT

echo "rounds=$ROUNDS pps=$PPS duration=${DUR}s iface=$GEN_IFACE teid=$TEID"
echo
printf '%-12s' 'round'; for n in "${NAMES[@]}"; do printf '%14s' "$n"; done; echo '   (ns/packet)'

for r in $(seq 1 "$ROUNDS"); do
    declare -a B_T B_C
    for i in "${!PINS[@]}"; do read -r t c <<<"$(stat_of "${PINS[$i]}")"; B_T[$i]=$t; B_C[$i]=$c; done

    ./test/qer_blast "$GEN_IFACE" "$PPS" "$DUR" "$TEID" 1 >/dev/null 2>&1

    printf '%-12s' "$r"
    for i in "${!PINS[@]}"; do
        read -r t c <<<"$(stat_of "${PINS[$i]}")"
        dt=$(( t - ${B_T[$i]} )); dc=$(( c - ${B_C[$i]} ))
        if [ "$dc" -gt 0 ]; then
            printf '%14s' "$(python3 -c "print(f'{$dt/$dc:.1f}')")"
        else
            printf '%14s' 'no-runs'
        fi
    done
    echo
done
