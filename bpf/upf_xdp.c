// SPDX-License-Identifier: GPL-2.0
// Minimal XDP UPF prototype: GTP-U uplink decap-classify
// Companion implementation for "eBPF-Driven Programmable Traffic Steering
// and In-Kernel Observability for 5G User Plane Functions".

#include "upf_maps.h"
#include <bpf/bpf_endian.h>

#define ETH_P_IP        0x0800
#define IPPROTO_UDP_X   17
#define GTPU_PORT       2152
#define GTPU_GPDU       0xff   /* G-PDU message type */

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

    /* Classification complete. Forwarding disposition (FAR/QER/URR) is
     * enforced by the TC ingress programme (upf_tc.c) after sk_buff
     * allocation, which independently re-derives TEID/session/PDR/FAR --
     * see upf_tc.c for why metadata is not propagated via skb->cb[]. */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
