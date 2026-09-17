#!/usr/bin/env bash
# QER contention sweep: per-CPU vs shared spin-locked token bucket.
#
# The independent variable is the number of NIC receive queues, set with
# `ethtool -L combined N`. An earlier version of this experiment instead
# varied the number of flows and simply recorded how many CPUs happened to
# be engaged, but RSS hashing made that vary between otherwise identical
# runs, so the core count was an uncontrolled nuisance variable rather than
# something being swept. Constraining the queue count makes the degree of
# concurrency an input to the experiment instead of an observation of it.
#
# Changing the queue count resets the NIC and tears down attached XDP/TC
# programmes, so the datapath is reloaded (and the agent restarted, since it
# caches fds for maps that the reload replaces) after every change.
#
# Usage: sudo bash test/qer_contention_sweep.sh [out.txt]
set -euo pipefail

CD="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CD"

OUT="${1:-results_native/qer_contention/raw_queues.txt}"
mkdir -p "$(dirname "$OUT")"
: > "$OUT"

IFACE=enp24s0f0
QUEUES=(1 2 4 8 16)
NFLOWS=32          # well above the queue count so every queue stays busy
REPEATS=3
DURATION=5
PPS=200000
MBR=2000000
BURST=65536

sysctl -w kernel.bpf_stats_enabled=1 >/dev/null

restart_agent() {
    pgrep -f 'loader/agen[t].py' | xargs -r kill 2>/dev/null || true
    sleep 1
    setsid -f python3 "loader/age""nt.py" --addr 127.0.0.1 --port 9090 \
        --initial 5 --out-ifindex 2 >/dev/null 2>&1
    sleep 3
}

build_variant() {
    rm -f bpf/upf_tc.o
    if [ "$1" = "shared" ]; then
        make bpf/upf_tc.o EXTRA_CFLAGS='-DUPF_QER_SHARED_LOCK' >/dev/null
    else
        make bpf/upf_tc.o >/dev/null
    fi
}

for VARIANT in percpu shared; do
    build_variant "$VARIANT"
    for Q in "${QUEUES[@]}"; do
        echo "=== variant=$VARIANT queues=$Q ==="
        ethtool -L "$IFACE" combined "$Q"
        sleep 2
        bash scripts/reload_all.sh "$IFACE" >/dev/null 2>&1
        restart_agent

        for R in $(seq 1 "$REPEATS"); do
            LINE=$(python3 test/qer_contention.py --nflows "$NFLOWS" --pps "$PPS" \
                    --duration "$DURATION" --mbr-bps "$MBR" --burst "$BURST" \
                    --label "$VARIANT")
            echo "queues=$Q rep=$R $LINE" | tee -a "$OUT"
        done
    done
done

echo "[+] sweep complete -> $OUT"
