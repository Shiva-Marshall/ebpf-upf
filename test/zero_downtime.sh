#!/usr/bin/env bash
# zero_downtime.sh
# Drive a steady GTP-U G-PDU stream at TARGET_PPS while installing N_RULES
# PFCP rules into the BPF maps mid-flight. Verify zero session disruption.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RESULTS="$HERE/../results"
mkdir -p "$RESULTS"

PORT=9090
DURATION=${DURATION:-10}
TARGET_PPS=${TARGET_PPS:-50000}
N_RULES=${N_RULES:-100}
TEID=${TEID:-0x1000}      # bootstrap TEID — should be a hit

read_metric() {
    curl -s "http://127.0.0.1:${PORT}/metrics" | awk -v stage="$1" '
        $0 ~ "stage=\""stage"\"" { print $NF }
    '
}

echo "=== Zero-downtime rule-update under live traffic ==="
echo "    duration=${DURATION}s  target_pps=${TARGET_PPS}  rules=${N_RULES}  teid=${TEID}"

# Snapshot
hit_before=$(read_metric hit)
miss_before=$(read_metric miss_teid)
parse_before=$(read_metric drop_parse)
ts_start=$(date +%s.%N)

# Start blast in the netns (background).  Output captured.
sudo -n ip netns exec upfns "$HERE/gtpu_blast" upf_ns "$TARGET_PPS" "$DURATION" "$TEID" \
    > "$RESULTS/zerodowntime_blast.stdout" 2> "$RESULTS/zerodowntime_blast.stderr" &
BLAST_PID=$!

# Wait until traffic is clearly running, then install rules
sleep $((DURATION/3))

echo "--- installing $N_RULES rules at t≈${DURATION}/3 ---"
sudo -n "$HERE/bench_rule_update" "$N_RULES" \
    "$RESULTS/zerodowntime_n${N_RULES}.csv" \
    | tee "$RESULTS/zerodowntime_bench.stdout"

wait "$BLAST_PID" 2>/dev/null || true
ts_end=$(date +%s.%N)

hit_after=$(read_metric hit)
miss_after=$(read_metric miss_teid)
parse_after=$(read_metric drop_parse)

hit_delta=$(( hit_after - hit_before ))
miss_delta=$(( miss_after - miss_before ))
parse_delta=$(( parse_after - parse_before ))

# Pull "sent" from blaster output
sent=$(awk '/^blast:/ {for(i=1;i<=NF;i++){if($i~/^sent=/){split($i,a,"=");print a[2]}}}' "$RESULTS/zerodowntime_blast.stderr")
sent=${sent:-0}

# loss % — what fraction of sent packets did NOT register as hits
if [ "$sent" -gt 0 ]; then
    loss_pct=$(awk -v s="$sent" -v h="$hit_delta" 'BEGIN{ if(s==0){print "n/a"}else{ printf "%.4f%%", (s-h)*100.0/s }}')
else
    loss_pct="n/a (no packets sent)"
fi

cat > "$RESULTS/zerodowntime_summary.txt" <<EOF
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
cat "$RESULTS/zerodowntime_summary.txt"
echo
echo "raw per-rule samples : $RESULTS/zerodowntime_n${N_RULES}.csv"
