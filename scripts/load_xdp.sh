#!/usr/bin/env bash
# Load and pin the BPF program + maps using bpftool, attach to host veth.
set -euo pipefail

BPFTOOL=/usr/lib/linux-tools/$(uname -r)/bpftool
OBJ="$(dirname "$0")/../bpf/upf_xdp.o"
PIN_BASE=/sys/fs/bpf/upf
HOST_IF=${HOST_IF:-upf_host}
MODE=${MODE:-xdpgeneric}    # generic XDP works on every NIC including veth

case "${1:-up}" in
  up)
    sudo mkdir -p "$PIN_BASE"
    # detach if anything already attached
    sudo ip link set dev "$HOST_IF" xdpgeneric off 2>/dev/null || true
    sudo ip link set dev "$HOST_IF" xdp        off 2>/dev/null || true
    # remove any stale pins
    sudo rm -rf "$PIN_BASE"/*
    # load ELF; pin program AND maps under $PIN_BASE
    sudo "$BPFTOOL" prog loadall "$OBJ" "$PIN_BASE" type xdp pinmaps "$PIN_BASE"
    # find what bpftool actually named the program (section name = "xdp")
    PROG_PIN="$PIN_BASE/xdp"
    if [ ! -e "$PROG_PIN" ]; then
        PROG_PIN=$(find "$PIN_BASE" -maxdepth 1 -type f | head -1)
    fi
    sudo ip link set dev "$HOST_IF" "$MODE" pinned "$PROG_PIN"
    echo "[+] attached $(basename "$PROG_PIN") to $HOST_IF (mode=$MODE)"
    echo "[+] pinned objects:"
    sudo ls -la "$PIN_BASE"
    echo "[+] attached:"
    sudo "$BPFTOOL" net show dev "$HOST_IF" 2>&1 || true
    ;;
  down)
    sudo ip link set dev "$HOST_IF" xdpgeneric off 2>/dev/null || true
    sudo ip link set dev "$HOST_IF" xdp        off 2>/dev/null || true
    sudo rm -rf "$PIN_BASE"/*
    echo "[+] detached and unpinned"
    ;;
  *)
    echo "usage: $0 [up|down]" >&2
    exit 2
    ;;
esac
