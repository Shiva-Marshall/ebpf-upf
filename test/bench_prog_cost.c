// SPDX-License-Identifier: GPL-2.0
//
// bench_prog_cost.c -- per-packet datapath cost via BPF_PROG_TEST_RUN.
//
// Why this exists. The wire-level generator harness (native_throughput.py +
// xdp_throughput_blast.c) measures a *closed loop* on a single host: the
// generator transmits from enp24s0f1, enp24s0f0 receives and runs the
// XDP/TC pipeline, and the FAR then redirects the decapsulated packet back
// out enp24s0f0 -- so every received packet also creates transmit work, on
// the same 24-core box the generator threads run on. Offered load, receive
// softirq load and redirect-transmit load therefore compete for the same
// cores, and the system settles wherever scheduling happens to put it: two
// identical 8-thread runs were observed to transmit 14.2M and 3.0M packets
// respectively. That equilibrium is not a property of the UPF datapath, so
// it is not a sound basis for a throughput claim.
//
// BPF_PROG_TEST_RUN removes every one of those confounders. The kernel runs
// the program `repeat` times in a tight loop on one synthetic packet and
// reports the total time spent inside the program, with no NIC, no driver,
// no softirq scheduling, no generator, and no redirect feedback. It is the
// mechanism the kernel's own selftests and the wider eBPF community use to
// benchmark program cost, and it is reproducible run to run.
//
// What it measures: the cost of the eBPF programs themselves -- parse,
// lookups, QER/URR accounting, decap. It deliberately does NOT include
// driver RX, DMA, skb allocation or wire time, so the derived per-core
// packet rate is an upper bound on what the datapath logic permits, not a
// prediction of achievable line rate. The paper states this scope
// explicitly rather than presenting it as an end-to-end throughput figure.
//
// Build: gcc -O2 -Wall -o bench_prog_cost bench_prog_cost.c -lbpf
// Usage: sudo ./bench_prog_cost [repeat] [rounds]

#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PIN_XDP "/sys/fs/bpf/upf/xdp_prog/xdp"
#define PIN_TC  "/sys/fs/bpf/upf/tc_prog/classifier"
#define PIN_TCE "/sys/fs/bpf/upf/tc_egress_prog/classifier"

struct __attribute__((packed)) ethhdr_x { uint8_t dst[6], src[6]; uint16_t proto; };
struct __attribute__((packed)) iphdr_x {
    uint8_t vihl, tos; uint16_t tot_len, id, frag_off;
    uint8_t ttl, protocol; uint16_t check; uint32_t saddr, daddr;
};
struct __attribute__((packed)) udphdr_x { uint16_t source, dest, len, check; };
struct __attribute__((packed)) gtphdr_x { uint8_t flags, msg_type; uint16_t length; uint32_t teid; };

static uint16_t ip_csum(void *data, int len) {
    uint32_t sum = 0; uint16_t *p = data;
    while (len >= 2) { sum += *p++; len -= 2; }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

/* Build the same 150-byte GTP-U G-PDU the wire-level generators emit, so the
 * cost measured here is for the identical packet shape used elsewhere. */
static int build_pkt(uint8_t *buf, uint32_t teid)
{
    int off = 0;
    struct ethhdr_x *eth = (void *)(buf + off); off += sizeof(*eth);
    memset(eth->dst, 0xFF, 6);
    memset(eth->src, 0x02, 6);
    eth->proto = htons(0x0800);

    struct iphdr_x *ip = (void *)(buf + off); off += sizeof(*ip);
    ip->vihl = 0x45; ip->ttl = 64; ip->protocol = 17;
    ip->saddr = inet_addr("10.99.0.2");
    ip->daddr = inet_addr("10.99.0.1");

    struct udphdr_x *udp = (void *)(buf + off); off += sizeof(*udp);
    udp->source = htons(31000); udp->dest = htons(2152); udp->check = 0;

    struct gtphdr_x *gtp = (void *)(buf + off); off += sizeof(*gtp);
    gtp->flags = 0x30; gtp->msg_type = 0xff; gtp->teid = htonl(teid);

    struct iphdr_x *iip = (void *)(buf + off); off += sizeof(*iip);
    iip->vihl = 0x45; iip->ttl = 64; iip->protocol = 17;
    iip->saddr = inet_addr("10.45.0.1");
    iip->daddr = inet_addr("8.8.8.8");

    memset(buf + off, 'X', 80);
    off += 80;

    int ip_total  = off - (int)sizeof(*eth);
    int udp_total = ip_total - (int)sizeof(*ip);
    int gtp_pl    = udp_total - (int)sizeof(*udp) - (int)sizeof(*gtp);
    int iip_total = ip_total - (int)sizeof(*ip) - (int)sizeof(*udp) - (int)sizeof(*gtp);
    ip->tot_len  = htons(ip_total);
    ip->check    = ip_csum(ip, sizeof(*ip));
    udp->len     = htons(udp_total);
    gtp->length  = htons(gtp_pl);
    iip->tot_len = htons(iip_total);
    iip->check   = ip_csum(iip, sizeof(*iip));
    return off;
}

/* For SCHED_CLS programs the kernel's test-run path calls eth_type_trans(),
 * which consumes the leading Ethernet header, leaving skb->data at L3. Our
 * TC programmes parse from L2 (as they do on a real clsact hook), so for
 * those we prepend one throwaway Ethernet header: the kernel strips the
 * dummy, and the programme then sees the genuine frame exactly as it would
 * on the wire. Without this the programme exits at its first h_proto check
 * after ~8 ns and measures nothing. Verified by the per-stage counters:
 * with the shim, tc_far_forward advances once per repeat; without it, not
 * at all. XDP needs no shim -- its test-run path does not pull L2. */
static int run_one(const char *pin, const char *label, uint8_t *pkt, int len,
                   uint32_t repeat, int rounds, int l2_shim)
{
    static uint8_t shimmed[1600];
    if (l2_shim) {
        struct ethhdr_x dummy;
        memset(dummy.dst, 0xFF, 6);
        memset(dummy.src, 0x02, 6);
        dummy.proto = htons(0x0800);
        memcpy(shimmed, &dummy, sizeof(dummy));
        memcpy(shimmed + sizeof(dummy), pkt, len);
        pkt = shimmed;
        len += (int)sizeof(dummy);
    }
    int fd = bpf_obj_get(pin);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", pin, strerror(errno));
        return -1;
    }

    /* XDP needs headroom for the 256-byte xdp_frame the kernel prepends. */
    static uint8_t out[2048];

    double best = 1e18, sum = 0;
    unsigned int last_retval = 0;
    for (int r = 0; r < rounds; r++) {
        DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
            .data_in = pkt,
            .data_size_in = len,
            .data_out = out,
            .data_size_out = sizeof(out),
            .repeat = repeat,
        );
        int err = bpf_prog_test_run_opts(fd, &opts);
        if (err) {
            fprintf(stderr, "%s: test_run failed: %s\n", label, strerror(errno));
            close(fd);
            return -1;
        }
        last_retval = opts.retval;
        double ns = (double)opts.duration;   /* avg ns per run, per kernel */
        sum += ns;
        if (ns < best) best = ns;
    }
    close(fd);
    printf("%-12s repeat=%u rounds=%d  mean=%.1f ns/pkt  best=%.1f ns/pkt  retval=%u\n",
           label, repeat, rounds, sum / rounds, best, last_retval);
    return 0;
}

int main(int argc, char **argv)
{
    uint32_t repeat = (argc > 1) ? (uint32_t)strtoul(argv[1], NULL, 0) : 1000000;
    int rounds = (argc > 2) ? atoi(argv[2]) : 5;

    uint8_t pkt[1500];
    int len = build_pkt(pkt, 0x9000);
    printf("packet: %d bytes (GTP-U G-PDU, TEID 0x9000)\n\n", len);

    run_one(PIN_XDP, "xdp_uplink", pkt, len, repeat, rounds, 0);
    run_one(PIN_TC,  "tc_ingress", pkt, len, repeat, rounds, 1);
    run_one(PIN_TCE, "tc_egress",  pkt, len, repeat, rounds, 1);
    return 0;
}
