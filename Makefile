CLANG    ?= clang
BPFTOOL  ?= /usr/lib/linux-tools/$(shell uname -r)/bpftool
ARCH     := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Pass EXTRA_CFLAGS=-DUPF_EMIT_DECISION_EVENTS to build upf_tc.o with the
# per-packet decision-audit perf event used only by the transactional-
# consistency concurrent-traffic experiment; off by default since
# per-packet perf events at line rate would themselves be a bottleneck.
BPF_CFLAGS := -O2 -g -target bpf \
              -D__TARGET_ARCH_$(ARCH) $(EXTRA_CFLAGS) \
              -I bpf -I /usr/include -I /usr/include/$(shell uname -m)-linux-gnu

OBJ := bpf/upf_xdp.o bpf/upf_tc.o bpf/upf_tc_egress.o

.PHONY: all clean vmlinux

all: vmlinux $(OBJ)

vmlinux: bpf/vmlinux.h

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

bpf/upf_xdp.o: bpf/upf_xdp.c bpf/upf_maps.h bpf/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf/upf_tc.o: bpf/upf_tc.c bpf/upf_maps.h bpf/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf/upf_tc_egress.o: bpf/upf_tc_egress.c bpf/upf_maps.h bpf/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f bpf/*.o bpf/vmlinux.h
