// SPDX-License-Identifier: GPL-2.0
//
// xdp_throughput_blast.c -- multi-threaded AF_PACKET GTP-U generator for the
// native-XDP throughput measurement (Phase 8).
//
// Why this exists rather than TRex: TRex/DPDK refuses to run on one port of
// this XXV710 while the sibling port of the same physical chip stays under
// the kernel driver ("i40e interface ... is under Linux and will interfere
// with TRex" -- a known DPDK/i40e restriction, not a config error). Since
// our own XDP program must stay under the kernel driver on enp24s0f0, TRex
// cannot share this card. The in-kernel pktgen module loads but does not
// create its debugfs control directory on this kernel build, for reasons
// not further chased down given time constraints. This generator is the
// fallback: N independent threads, each its own raw AF_PACKET socket with
// PACKET_QDISC_BYPASS (skips the qdisc layer entirely) and PACKET_FANOUT-free
// batched sendmmsg() (far fewer syscalls than the single-threaded sendto()
// loop used elsewhere in this repo), each thread using a distinct outer UDP
// source port so RSS on the receive side spreads flows across queues/CPUs --
// same reasoning as test/qer_blast.c.
//
// This does not claim to reach 25GbE line rate; it reports whatever it
// actually achieves, which is what gets measured and reported (see
// results_native/native_throughput/summary.md for the achieved ceiling and
// why it is generator- not UPF-limited, exactly as the reference
// benchmarking framework on this host reports its own "generator_ceiling").
//
// Build: gcc -O3 -Wall -pthread -o xdp_throughput_blast xdp_throughput_blast.c
// Usage: sudo ./xdp_throughput_blast <iface> <nthreads> <duration_s> <teid_base_hex> <frame_bytes>

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define BATCH 64

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

static const char *g_iface;
static uint32_t g_teid_base;
static int g_frame_bytes;
static long g_duration_s;
static atomic_long g_sent_total = 0;
static atomic_long g_err_total = 0;

struct thread_arg { int idx; int cpu; };

static void *worker(void *argp) {
    struct thread_arg *a = argp;

    if (a->cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(a->cpu, &set);
        pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    }

    int sk = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sk < 0) { perror("socket"); return NULL; }

    int bypass = 1;
    setsockopt(sk, SOL_PACKET, PACKET_QDISC_BYPASS, &bypass, sizeof(bypass));

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, g_iface, IFNAMSIZ - 1);
    ioctl(sk, SIOCGIFINDEX, &ifr);
    int ifindex = ifr.ifr_ifindex;
    ioctl(sk, SIOCGIFHWADDR, &ifr);
    uint8_t src_mac[6];
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    struct sockaddr_ll sa = {0};
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_IP);
    sa.sll_ifindex = ifindex;
    sa.sll_halen = 6;
    memset(sa.sll_addr, 0xFF, 6);

    uint8_t buf[1500] = {0};
    int off = 0;
    struct ethhdr_x *eth = (void *)(buf + off); off += sizeof(*eth);
    memset(eth->dst, 0xFF, 6);
    memcpy(eth->src, src_mac, 6);
    eth->proto = htons(0x0800);

    struct iphdr_x *ip = (void *)(buf + off); off += sizeof(*ip);
    ip->vihl = 0x45; ip->ttl = 64; ip->protocol = 17;
    ip->saddr = inet_addr("10.99.0.2");
    ip->daddr = inet_addr("10.99.0.1");

    struct udphdr_x *udp = (void *)(buf + off); off += sizeof(*udp);
    udp->source = htons(31000 + a->idx * 11);
    udp->dest = htons(2152);
    udp->check = 0;

    struct gtphdr_x *gtp = (void *)(buf + off); off += sizeof(*gtp);
    gtp->flags = 0x30; gtp->msg_type = 0xff;
    gtp->teid = htonl(g_teid_base + a->idx);

    struct iphdr_x *iip = (void *)(buf + off); off += sizeof(*iip);
    iip->vihl = 0x45; iip->ttl = 64; iip->protocol = 17;
    iip->saddr = inet_addr("10.45.0.1");
    iip->daddr = inet_addr("8.8.8.8");
    off += sizeof(*iip);

    int header_bytes = off;
    int pad = g_frame_bytes - header_bytes - 4 /* FCS, not sent by us but counted in frame_bytes */;
    if (pad < 0) pad = 0;
    memset(buf + off, 'X', pad);
    off += pad;
    int total_pkt = off;

    int ip_total = total_pkt - (int)sizeof(*eth);
    int udp_total = ip_total - (int)sizeof(*ip);
    int gtp_payload = udp_total - (int)sizeof(*udp) - (int)sizeof(*gtp);
    int iip_total = ip_total - (int)sizeof(*ip) - (int)sizeof(*udp) - (int)sizeof(*gtp);
    ip->tot_len = htons(ip_total);
    ip->check = ip_csum(ip, sizeof(*ip));
    udp->len = htons(udp_total);
    gtp->length = htons(gtp_payload);
    iip->tot_len = htons(iip_total);
    iip->check = ip_csum(iip, sizeof(*iip));

    // sendmmsg batch: BATCH copies of the same packet, one syscall per batch.
    struct mmsghdr msgs[BATCH];
    struct iovec iovs[BATCH];
    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < BATCH; i++) {
        iovs[i].iov_base = buf;
        iovs[i].iov_len = total_pkt;
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &sa;
        msgs[i].msg_hdr.msg_namelen = sizeof(sa);
    }

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    long sent = 0, errs = 0;

    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000000000L + (now.tv_nsec - start.tv_nsec);
        if (elapsed >= g_duration_s * 1000000000L) break;

        int r = sendmmsg(sk, msgs, BATCH, 0);
        if (r < 0) { errs++; continue; }
        sent += r;
        if (r < BATCH) errs += (BATCH - r);
    }

    atomic_fetch_add(&g_sent_total, sent);
    atomic_fetch_add(&g_err_total, errs);
    close(sk);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "usage: %s <iface> <nthreads> <duration_s> <teid_base_hex> <frame_bytes>\n", argv[0]);
        return 2;
    }
    g_iface = argv[1];
    int nthreads = atoi(argv[2]);
    g_duration_s = atol(argv[3]);
    g_teid_base = (uint32_t)strtoul(argv[4], NULL, 0);
    g_frame_bytes = atoi(argv[5]);

    pthread_t tids[256];
    struct thread_arg args[256];
    if (nthreads > 256) nthreads = 256;

    for (int i = 0; i < nthreads; i++) {
        args[i].idx = i;
        args[i].cpu = 16 + (i % 8);   // cores 16-23: away from isolcpus RX-heavy 0-15 range
        pthread_create(&tids[i], NULL, worker, &args[i]);
    }
    for (int i = 0; i < nthreads; i++) pthread_join(tids[i], NULL);

    double mpps = (double)g_sent_total / (double)g_duration_s / 1e6;
    double gbps = mpps * g_frame_bytes * 8.0 / 1e3;
    printf("blast_sent=%ld blast_errors=%ld duration_s=%ld nthreads=%d frame_bytes=%d "
           "achieved_mpps=%.4f achieved_gbps=%.4f\n",
           (long)g_sent_total, (long)g_err_total, g_duration_s, nthreads, g_frame_bytes, mpps, gbps);
    return 0;
}
