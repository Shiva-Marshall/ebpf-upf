#!/usr/bin/env bash
# contention_sweep.sh
# Measure rule-update p50/p95/p99 while blasting GTP-U at varying rates.
# Output: one CSV row per (rate, batch).

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RESULTS="$HERE/../results"
mkdir -p "$RESULTS"

OUT="$RESULTS/contention_sweep.csv"
echo "target_pps,n_rules,total_ms,mean_us,min_us,p50_us,p95_us,p99_us,max_us,blast_sent,hit_delta,miss_delta" > "$OUT"

read_metric() {
    curl -s "http://127.0.0.1:9090/metrics" | awk -v stage="$1" '
        $0 ~ "stage=\""stage"\"" { print $NF }
    '
}

start_agent_if_needed() {
    if ! curl -fs -o /dev/null http://127.0.0.1:9090/healthz 2>/dev/null; then
        echo "[~] starting agent ..."
        sudo -n nohup python3 "$HERE/../loader/agent.py" --addr 127.0.0.1 --port 9090 --initial 10 \
            > /tmp/agent.log 2>&1 &
        sleep 1.5
    fi
}

run_one() {
    local rate=$1 n_rules=$2

    local hit_b miss_b
    hit_b=$(read_metric hit)
    miss_b=$(read_metric miss_teid)

    if [ "$rate" = "0" ]; then
        # No background traffic — pure rule-update timing
        local out
        out=$(sudo -n "$HERE/bench_rule_update" "$n_rules" "$RESULTS/contention_n${n_rules}_rate${rate}.csv" 2>/dev/null)
        local sent=0
    else
        # Start blast in netns, wait for steady-state, then run bench.
        sudo -n ip netns exec upfns "$HERE/gtpu_blast" upf_ns "$rate" 8 0x1000 \
            > /tmp/blast.out 2> /tmp/blast.err &
        local bp=$!
        sleep 2
        local out
        out=$(sudo -n "$HERE/bench_rule_update" "$n_rules" "$RESULTS/contention_n${n_rules}_rate${rate}.csv" 2>/dev/null)
        wait $bp 2>/dev/null || true
        local sent
        sent=$(awk '/^blast:/ {for(i=1;i<=NF;i++){if($i~/^sent=/){split($i,a,"=");print a[2]}}}' /tmp/blast.err)
        sent=${sent:-0}
    fi

    # Parse the bench's single output line:
    # N=100 total=0.520 ms per-rule mean=5.2 us min=3.5 p50=4.1 p95=5.4 p99=5.7 max=7.1
    local total mean min p50 p95 p99 max
    total=$(echo "$out" | grep -oE 'total=[0-9.]+'        | head -1 | cut -d= -f2)
    mean=$(echo  "$out" | grep -oE 'mean=[0-9.]+'         | head -1 | cut -d= -f2)
    min=$(echo   "$out" | grep -oE 'min=[0-9.]+'          | head -1 | cut -d= -f2)
    p50=$(echo   "$out" | grep -oE 'p50=[0-9.]+'          | head -1 | cut -d= -f2)
    p95=$(echo   "$out" | grep -oE 'p95=[0-9.]+'          | head -1 | cut -d= -f2)
    p99=$(echo   "$out" | grep -oE 'p99=[0-9.]+'          | head -1 | cut -d= -f2)
    max=$(echo   "$out" | grep -oE 'max=[0-9.]+'          | head -1 | cut -d= -f2)
    sleep 0.5

    local hit_a miss_a
    hit_a=$(read_metric hit)
    miss_a=$(read_metric miss_teid)
    local hit_d=$(( hit_a - hit_b ))
    local miss_d=$(( miss_a - miss_b ))
    sent=${sent:-0}

    echo "${rate},${n_rules},${total:-0},${mean:-0},${min:-0},${p50:-0},${p95:-0},${p99:-0},${max:-0},${sent},${hit_d},${miss_d}" \
        | tee -a "$OUT"
}

echo "=== rule-update tail latency vs concurrent traffic rate ==="
start_agent_if_needed

# Sweep over 4 traffic rates and 3 batch sizes.
for rate in 0 10000 50000 100000 ; do
    for n in 100 500 1000 ; do
        run_one "$rate" "$n"
    done
done

echo
echo "[+] CSV: $OUT"
column -t -s, "$OUT"
