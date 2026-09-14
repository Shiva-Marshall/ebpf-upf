// SPDX-License-Identifier: GPL-2.0
// upf_tc.c — TC ingress programme: PDR/FAR enforcement + GTP-U decapsulation.
//
// Attaches to the clsact/ingress hook of the same interface the XDP
// programme runs on. By the time a packet reaches here via XDP_PASS, XDP
// has already dropped every G-PDU packet with an unresolvable TEID or PDR
// (see upf_xdp.c) -- so only three kinds of traffic arrive: non-GTP UDP,
// GTP-U control messages, and known-TEID G-PDU traffic. This programme
// re-parses the packet and re-derives TEID/session/PDR/FAR independently
// of XDP rather than relying on skb->cb[]/metadata propagation from XDP
// (which is driver- and kernel-version-dependent); the extra hash lookups
// are O(1) and this keeps the two hooks decoupled and independently
// testable, at the cost of parsing the header twice. A TC-side miss can
// only happen if map state changed between the XDP and TC lookups (a race
// with a concurrent PFCP rule update, see Section on transactional
// consistency) -- we count it but do not drop, since we cannot
// distinguish a benign race from anything adversarial at this layer, and
// dropping would be strictly worse than letting the kernel stack see the
// packet unmodified.

#include "upf_maps.h"
#include <bpf/bpf_endian.h>

/* struct ethhdr/iphdr/udphdr already come from vmlinux.h (BTF-derived);
 * including the regular linux/if_ether.h & co. on top conflicts with those
 * definitions, so we only pull in the handful of TC_ACT_* macros we need
 * (normally from linux/pkt_cls.h) rather than the whole header. */
#define TC_ACT_OK_X         0
#define TC_ACT_SHOT_X       2
#define TC_ACT_REDIRECT_X   7

#define ETH_P_IP_X      0x0800
#define IPPROTO_UDP_X   17
#define GTPU_PORT_X     2152
#define GTPU_GPDU_X     0xff
#define BPF_ADJ_ROOM_MAC_X            1  /* was NET_X=0: adjusts below L3, kept stale outer IP header */
#define BPF_F_ADJ_ROOM_FIXED_GSO_X    (1ULL << 0)

/* Strip `outer_hdr_len` bytes of outer IP/UDP/GTP-U header (leaving the
 * Ethernet header and the inner IP packet intact), then redirect out the
 * FAR's configured egress interface. */
static __always_inline int upf_far_forward(struct __sk_buff *skb, __u32 far_id,
                                            __u32 outer_hdr_len)
{
    if (bpf_skb_adjust_room(skb, -(int)outer_hdr_len, BPF_ADJ_ROOM_MAC_X,
                             BPF_F_ADJ_ROOM_FIXED_GSO_X) < 0) {
        bump(M_TC_DECAP_ERR);
        return TC_ACT_SHOT_X;
    }

    struct far_val *far = bpf_map_lookup_elem(&far_table, &far_id);
    if (!far) {
        /* far_table entry vanished mid-flight (concurrent delete) */
        bump(M_TC_DECAP_ERR);
        return TC_ACT_SHOT_X;
    }

    bump(M_TC_FAR_FORWARD);
    int ret = bpf_redirect(far->out_ifindex, 0);
    if (ret != TC_ACT_REDIRECT_X)
        bump(M_TC_REDIRECT_ERR);
    return ret;
}

SEC("classifier")
int upf_tc_ingress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK_X;
    if (eth->h_proto != bpf_htons(ETH_P_IP_X))
        return TC_ACT_OK_X;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK_X;
    if (ip->protocol != IPPROTO_UDP_X)
        return TC_ACT_OK_X;

    __u32 ihl_bytes = ip->ihl * 4;
    if (ihl_bytes < sizeof(*ip))
        return TC_ACT_OK_X;
    void *l4 = (void *)ip + ihl_bytes;
    if (l4 + sizeof(struct udphdr) > data_end)
        return TC_ACT_OK_X;

    struct udphdr *udp = l4;
    if (udp->dest != bpf_htons(GTPU_PORT_X))
        return TC_ACT_OK_X;       /* non-GTP: not ours, leave for the stack */

    void *gtp = (void *)(udp + 1);
    if (gtp + 8 > data_end)
        return TC_ACT_OK_X;
    __u8 msg_type = *(__u8 *)(gtp + 1);
    if (msg_type != GTPU_GPDU_X)
        return TC_ACT_OK_X;       /* GTP-U control: not ours */

    __u32 teid_be;
    __builtin_memcpy(&teid_be, gtp + 4, 4);
    __u32 teid = bpf_ntohl(teid_be);

    struct session_val *sess = bpf_map_lookup_elem(&teid_session, &teid);
    if (!sess) {
        bump(M_TC_MISS_FAR);
        return TC_ACT_OK_X;       /* race with a concurrent rule update */
    }
    struct pdr_val *pdr = bpf_map_lookup_elem(&pdr_table, &sess->pdr_id);
    if (!pdr) {
        bump(M_TC_MISS_FAR);
        return TC_ACT_OK_X;
    }
    struct far_val *far = bpf_map_lookup_elem(&far_table, &pdr->far_id);
    if (!far) {
        bump(M_TC_MISS_FAR);
        return TC_ACT_OK_X;
    }

    if (far->action == FAR_DROP) {
        bump(M_TC_FAR_DROP);
        return TC_ACT_SHOT_X;
    }

    if (far->action == FAR_BUFFER) {
        /* Full design: bpf_sk_redirect_map() to a userspace socket + perf
         * event notification to the PFCP agent (Section on observability).
         * Not yet implemented: pass through unbuffered for now. */
        bump(M_TC_FAR_BUFFER);
        return TC_ACT_OK_X;
    }

    /* FAR_FORWARD: strip the outer IP/UDP/GTP-U header, then redirect. */
    __u32 outer_hdr_len = ihl_bytes + (__u32)sizeof(struct udphdr) + 8;
    return upf_far_forward(skb, pdr->far_id, outer_hdr_len);
}

char _license[] SEC("license") = "GPL";
