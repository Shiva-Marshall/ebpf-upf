// SPDX-License-Identifier: GPL-2.0
// Minimal XDP UPF prototype: GTP-U uplink decap-classify
// Companion implementation for "eBPF-Driven Programmable Traffic Steering
// and In-Kernel Observability for 5G User Plane Functions".

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP        0x0800
#define IPPROTO_UDP_X   17
#define GTPU_PORT       2152
#define GTPU_GPDU       0xff   /* G-PDU message type */

#define MAX_TEIDS       65536
#define MAX_PDRS        4096

/* ------------- Shared types (must match userspace) ------------- */

struct session_val {
    __u32 pdr_id;
    __u32 qer_id;
    __u32 far_id;
    __u32 _pad;
};

struct pdr_val {
    __u32 far_id;
    __u32 qer_id;
    __u32 precedence;
    __u32 _pad;
};

enum metric_idx {
    M_RX_TOTAL = 0,
    M_RX_GTPU,
    M_RX_GPDU,
    M_HIT,
    M_MISS_TEID,
    M_MISS_PDR,
    M_PASS_NONGTP,
    M_PASS_CTRL,
    M_DROP_PARSE,
    M_MAX,
};

/* ------------- Maps ------------- */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   __u32);     /* TEID (host order) */
    __type(value, struct session_val);
    __uint(max_entries, MAX_TEIDS);
} teid_session SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u32);     /* PDR id */
    __type(value, struct pdr_val);
    __uint(max_entries, MAX_PDRS);
} pdr_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,   __u32);
    __type(value, __u64);
    __uint(max_entries, M_MAX);
} metrics SEC(".maps");

/* ------------- Helpers ------------- */

static __always_inline void bump(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&metrics, &idx);
    if (v) __sync_fetch_and_add(v, 1);
}

/* ------------- Main XDP program ------------- */

SEC("xdp")
int upf_xdp_uplink(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    bump(M_RX_TOTAL);

    /* L2: Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bump(M_DROP_PARSE);
        return XDP_DROP;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* L3: IPv4 */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        bump(M_DROP_PARSE);
        return XDP_DROP;
    }
    if (ip->protocol != IPPROTO_UDP_X)
        return XDP_PASS;

    /* Validate IHL and skip options */
    __u32 ihl_bytes = ip->ihl * 4;
    if (ihl_bytes < sizeof(*ip)) {
        bump(M_DROP_PARSE);
        return XDP_DROP;
    }
    void *l4 = (void *)ip + ihl_bytes;
    if (l4 + sizeof(struct udphdr) > data_end) {
        bump(M_DROP_PARSE);
        return XDP_DROP;
    }

    /* L4: UDP */
    struct udphdr *udp = l4;
    if (udp->dest != bpf_htons(GTPU_PORT)) {
        bump(M_PASS_NONGTP);
        return XDP_PASS;
    }

    bump(M_RX_GTPU);

    /* GTP-U: 8-byte mandatory header */
    void *gtp = (void *)(udp + 1);
    if (gtp + 8 > data_end) {
        bump(M_DROP_PARSE);
        return XDP_DROP;
    }
    __u8  flags    = *(__u8 *)(gtp + 0);
    __u8  msg_type = *(__u8 *)(gtp + 1);
    __u32 teid_be;
    __builtin_memcpy(&teid_be, gtp + 4, 4);
    __u32 teid = bpf_ntohl(teid_be);

    /* Only G-PDU traffic gets the fast path; control messages go to kernel. */
    if (msg_type != GTPU_GPDU) {
        bump(M_PASS_CTRL);
        return XDP_PASS;
    }
    bump(M_RX_GPDU);

    /* (We tolerate any value of `flags`; extension-header parsing is future work.) */
    (void)flags;

    /* Session lookup */
    struct session_val *sess = bpf_map_lookup_elem(&teid_session, &teid);
    if (!sess) {
        bump(M_MISS_TEID);
        return XDP_DROP;
    }

    /* PDR lookup */
    struct pdr_val *pdr = bpf_map_lookup_elem(&pdr_table, &sess->pdr_id);
    if (!pdr) {
        bump(M_MISS_PDR);
        return XDP_DROP;
    }

    bump(M_HIT);

    /* For the prototype we PASS the packet to the kernel after lookup
       (a production build would XDP_REDIRECT to N6 after decap). */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
