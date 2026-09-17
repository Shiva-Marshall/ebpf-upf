#!/usr/bin/env bash
# zero_downtime_native.sh -- native-XDP-testbed re-run of zero_downtime.sh
# (Table 6). Same logic and same output format; only the traffic path
# differs: the original drives gtpu_blast inside a "upfns" netns over a
# veth pair (generic XDP), this drives it over the physical loop cable
# from enp24s0f1 into enp24s0f0 (native XDP), both in the root netns.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RESULTS="$HERE/../results_native/vm_tables_rerun"
mkdir -p "$RESULTS"

PORT=9090
DURATION=${DURATION:-10}
TARGET_PPS=${TARGET_PPS:-50000}
N_RULES=${N_RULES:-100}
TEID=${TEID:-0x1000}
GEN_IFACE=${GEN_IFACE:-enp24s0f1}

read_metric() {
    curl -s "http://127.0.0.1:${PORT}/metrics" | awk -v stage="$1" '
        $0 ~ "stage=\""stage"\"" { print $NF }
    '
}

echo "=== Zero-downtime rule-update under live traffic (native-XDP testbed) ==="
echo "    duration=${DURATION}s  target_pps=${TARGET_PPS}  rules=${N_RULES}  teid=${TEID}  gen_iface=${GEN_IFACE}"

hit_before=$(read_metric hit)
miss_before=$(read_metric miss_teid)
parse_before=$(read_metric drop_parse)
ts_start=$(date +%s.%N)

sudo -n "$HERE/gtpu_blast" "$GEN_IFACE" "$TARGET_PPS" "$DURATION" "$TEID" \
    > "$RESULTS/zerodowntime_native_blast.stdout" 2> "$RESULTS/zerodowntime_native_blast.stderr" &
BLAST_PID=$!

sleep $((DURATION/3))

echo "--- installing $N_RULES rules at t~${DURATION}/3 ---"
sudo -n "$HERE/bench_rule_update" "$N_RULES" \
    "$RESULTS/zerodowntime_native_n${N_RULES}.csv" \
    | tee "$RESULTS/zerodowntime_native_bench.stdout"

wait "$BLAST_PID" 2>/dev/null || true
ts_end=$(date +%s.%N)

hit_after=$(read_metric hit)
miss_after=$(read_metric miss_teid)
parse_after=$(read_metric drop_parse)

hit_delta=$(( hit_after - hit_before ))
miss_delta=$(( miss_after - miss_before ))
parse_delta=$(( parse_after - parse_before ))

sent=$(awk '/^blast:/ {for(i=1;i<=NF;i++){if($i~/^sent=/){split($i,a,"=");print a[2]}}}' "$RESULTS/zerodowntime_native_blast.stderr" 2>/dev/null || true)
sent=${sent:-0}

if [ "$sent" -gt 0 ]; then
    loss_pct=$(awk -v s="$sent" -v h="$hit_delta" 'BEGIN{ if(s==0){print "n/a"}else{ printf "%.4f%%", (s-h)*100.0/s }}')
else
    loss_pct="n/a (no packets sent)"
fi

cat > "$RESULTS/zerodowntime_native_summary.txt" <<EOF
testbed             : native-XDP (Intel XXV710/i40e, physical loop enp24s0f1->enp24s0f0)
duration_s          : ${DURATION}
target_pps          : ${TARGET_PPS}
rules_installed     : ${N_RULES}
packets_sent_blast  : ${sent}
hit_packets_delta   : ${hit_delta}
miss_packets_delta  : ${miss_delta}
parse_drop_delta    : ${parse_delta}
loss_vs_sent        : ${loss_pct}
wall_clock_seconds  : $(awk -v a=$ts_start -v b=$ts_end 'BEGIN{printf "%.3f", b-a}')
EOF

echo
echo "=== summary ==="
cat "$RESULTS/zerodowntime_native_summary.txt"
echo
echo "raw per-rule samples : $RESULTS/zerodowntime_native_n${N_RULES}.csv"
