#!/usr/bin/env bash
# contention_sweep_repeated.sh
# Run the contention sweep R times and emit per-cell aggregates (median).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RESULTS="$HERE/../results"
mkdir -p "$RESULTS"

R=${R:-5}
RAW="$RESULTS/contention_repeats_raw.csv"
AGG="$RESULTS/contention_repeats_agg.csv"

echo "run,target_pps,n_rules,total_ms,mean_us,min_us,p50_us,p95_us,p99_us,max_us,blast_sent,hit_d,miss_d" > "$RAW"

read_metric() {
    curl -s "http://127.0.0.1:9090/metrics" | awk -v stage="$1" '
        $0 ~ "stage=\""stage"\"" { print $NF }
    '
}

start_agent() {
    if ! curl -fs -o /dev/null http://127.0.0.1:9090/healthz 2>/dev/null; then
        sudo -n nohup python3 "$HERE/../loader/agent.py" --addr 127.0.0.1 --port 9090 --initial 10 \
            > /tmp/agent.log 2>&1 &
        sleep 2
    fi
}

run_one() {
    local run=$1 rate=$2 n_rules=$3
    local hit_b miss_b
    hit_b=$(read_metric hit)
    miss_b=$(read_metric miss_teid)

    local sent=0
    if [ "$rate" = "0" ]; then
        local out
        out=$(sudo -n "$HERE/bench_rule_update" "$n_rules" /dev/null 2>/dev/null)
    else
        sudo -n ip netns exec upfns "$HERE/gtpu_blast" upf_ns "$rate" 6 0x1000 \
            > /tmp/blast.out 2> /tmp/blast.err &
        local bp=$!
        sleep 1.5
        local out
        out=$(sudo -n "$HERE/bench_rule_update" "$n_rules" /dev/null 2>/dev/null)
        wait $bp 2>/dev/null || true
        sent=$(awk '/^blast:/ {for(i=1;i<=NF;i++){if($i~/^sent=/){split($i,a,"=");print a[2]}}}' /tmp/blast.err)
        sent=${sent:-0}
    fi

    local total mean min p50 p95 p99 max
    total=$(echo "$out" | grep -oE 'total=[0-9.]+'   | head -1 | cut -d= -f2)
    mean=$(echo  "$out" | grep -oE 'mean=[0-9.]+'    | head -1 | cut -d= -f2)
    min=$(echo   "$out" | grep -oE 'min=[0-9.]+'     | head -1 | cut -d= -f2)
    p50=$(echo   "$out" | grep -oE 'p50=[0-9.]+'     | head -1 | cut -d= -f2)
    p95=$(echo   "$out" | grep -oE 'p95=[0-9.]+'     | head -1 | cut -d= -f2)
    p99=$(echo   "$out" | grep -oE 'p99=[0-9.]+'     | head -1 | cut -d= -f2)
    max=$(echo   "$out" | grep -oE 'max=[0-9.]+'     | head -1 | cut -d= -f2)

    sleep 0.3
    local hit_a miss_a hit_d miss_d
    hit_a=$(read_metric hit) ; miss_a=$(read_metric miss_teid)
    hit_d=$(( hit_a  - hit_b ))
    miss_d=$(( miss_a - miss_b ))

    echo "${run},${rate},${n_rules},${total:-0},${mean:-0},${min:-0},${p50:-0},${p95:-0},${p99:-0},${max:-0},${sent},${hit_d},${miss_d}" \
        | tee -a "$RAW"
}

start_agent
echo "=== contention sweep, R=$R repeats ==="
for run in $(seq 1 $R) ; do
    for rate in 0 10000 50000 100000 ; do
        for n in 100 500 1000 ; do
            run_one "$run" "$rate" "$n"
        done
    done
done

echo
echo "[+] raw: $RAW (aggregate on host)"
