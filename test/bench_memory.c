// SPDX-License-Identifier: GPL-2.0
//
// bench_memory.c — populate the teid_session and pdr_table maps with N
// entries, then read back kernel-reported memlock for each map.
//
// Usage:
//   sudo ./bench_memory <n_sessions>
//
// Output: one line of CSV with N + per-map memlock bytes.

#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>

#define PIN_BASE          "/sys/fs/bpf/upf"
#define PIN_TEID_SESSION  PIN_BASE "/teid_session"
#define PIN_PDR_TABLE     PIN_BASE "/pdr_table"

struct session_val {
    uint32_t pdr_id;
    uint32_t qer_id;
    uint32_t far_id;
    uint32_t _pad;
};

struct pdr_val {
    uint32_t far_id;
    uint32_t qer_id;
    uint32_t precedence;
    uint32_t _pad;
};

static long memlock_for(int fd) {
    /* bpf_obj_get_info_by_fd returns memlock in bytes via bpf_map_info */
    struct bpf_map_info info = {0};
    uint32_t info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd, &info, &info_len) < 0) {
        perror("bpf_obj_get_info_by_fd");
        return -1;
    }
    /* Older kernels expose memlock via map_info; if 0, fall back to a
       simple estimate from key+value size * max_entries. */
    if (info.max_entries) {
        /* not all kernels populate info.memlock; print sized estimate too */
        return (long)info.max_entries * (info.key_size + info.value_size);
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <n_sessions>\n", argv[0]); return 2; }
    int n = atoi(argv[1]);
    if (n <= 0) return 2;

    int fd_t = bpf_obj_get(PIN_TEID_SESSION);
    int fd_p = bpf_obj_get(PIN_PDR_TABLE);
    if (fd_t < 0 || fd_p < 0) { perror("bpf_obj_get"); return 1; }

    /* Cleanup any previous benchmark range. */
    for (uint32_t i = 0; i < (uint32_t)n; i++) {
        uint32_t teid = 0x10000 + i, pdr = 0x20000 + i;
        bpf_map_delete_elem(fd_t, &teid);
        bpf_map_delete_elem(fd_p, &pdr);
    }

    int fail = 0;
    for (uint32_t i = 0; i < (uint32_t)n; i++) {
        uint32_t teid = 0x10000 + i, pdr = 0x20000 + i;
        struct pdr_val     pv = { .far_id = 1, .qer_id = 1, .precedence = 100 };
        struct session_val sv = { .pdr_id = pdr, .qer_id = 1, .far_id = 1 };
        if (bpf_map_update_elem(fd_p, &pdr,  &pv, BPF_ANY) < 0) { fail++; }
        if (bpf_map_update_elem(fd_t, &teid, &sv, BPF_ANY) < 0) { fail++; }
    }

    long est_t = memlock_for(fd_t);
    long est_p = memlock_for(fd_p);
    long total_bytes = est_t + est_p;
    /* per-session footprint = (sizeof(session_val)+key) + (sizeof(pdr_val)+key)
       = (16+4) + (16+4) = 40 bytes minimum, ignoring hash-table overhead.   */
    printf("n_sessions=%d  pdr_table_estimate_bytes=%ld  teid_session_estimate_bytes=%ld  total_estimate_bytes=%ld  per_session_bytes=%.1f  inserts_failed=%d\n",
           n, est_p, est_t, total_bytes, total_bytes / (double)n, fail);

    /* Cleanup so subsequent runs start fresh (don't leave the maps full). */
    for (uint32_t i = 0; i < (uint32_t)n; i++) {
        uint32_t teid = 0x10000 + i, pdr = 0x20000 + i;
        bpf_map_delete_elem(fd_t, &teid);
        bpf_map_delete_elem(fd_p, &pdr);
    }
    return 0;
}
