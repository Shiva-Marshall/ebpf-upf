#!/usr/bin/env bash
# Create an isolated netns with a veth pair so we can drive XDP without
# touching docker / k8s / free5GC interfaces.
set -euo pipefail

NS=upfns
HOST_IF=upf_host
NS_IF=upf_ns

cleanup() {
    sudo ip netns del "$NS" 2>/dev/null || true
    sudo ip link del "$HOST_IF" 2>/dev/null || true
}

case "${1:-up}" in
  up)
    cleanup
    sudo ip netns add "$NS"
    sudo ip link add "$HOST_IF" type veth peer name "$NS_IF" netns "$NS"
    sudo ip addr add 10.99.0.1/24 dev "$HOST_IF"
    sudo ip link set "$HOST_IF" up
    sudo ip -n "$NS" addr add 10.99.0.2/24 dev "$NS_IF"
    sudo ip -n "$NS" link set "$NS_IF" up
    sudo ip -n "$NS" link set lo up
    # Disable IPv6 RA / autoconf in our namespace to keep things quiet
    echo "veth pair up: $HOST_IF <-> $NS_IF (in netns $NS)"
    ip -br link show "$HOST_IF"
    ;;
  down)
    cleanup
    echo "netns $NS torn down"
    ;;
  *)
    echo "usage: $0 [up|down]" >&2
    exit 2
    ;;
esac
