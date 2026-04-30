# ebpf-upf-prototype

A reference prototype implementing the architecture described in:

> **eBPF-Driven Programmable Traffic Steering and In-Kernel Observability for 5G User Plane Functions: An Architectural Investigation.**
> S. Valia, V.K. Rathi, S. Pathak, N.K. Rajput. *IEEE Access* (under review), 2026.

This repository contains the XDP eBPF data-plane, a Python control-plane stub
that translates synthetic PFCP rules into BPF map entries, a
Prometheus-compatible `/metrics` endpoint, syscall-level benchmarking
harnesses, and an AF_PACKET-based GTP-U traffic generator. It reproduces the
empirical evaluation in §VIII of the paper.

## Contents

| Path                         | What it is                                                                  |
|------------------------------|-----------------------------------------------------------------------------|
| `bpf/upf_xdp.c`              | XDP eBPF program: GTP-U parsing, TEID lookup, per-stage metrics             |
| `loader/agent.py`            | Control-plane stub: populates BPF maps, exposes `/metrics` and `/healthz`   |
| `test/bench_rule_update.c`   | Syscall-level rule-update timing harness                                    |
| `test/bench_memory.c`        | BPF map memory-footprint probe                                              |
| `test/gtpu_blast.c`          | AF_PACKET GTP-U G-PDU traffic generator (~1.5×10⁵ pps single-threaded)      |
| `test/send_gtpu.py`          | Scapy-based functional-test packet injector                                 |
| `test/zero_downtime.sh`      | End-to-end driver for the zero-downtime validation (Table V in the paper)   |
| `test/contention_sweep_repeated.sh` | 5× repeated rule-update sweep across traffic rates                   |
| `scripts/setup_netns.sh`     | Create isolated netns + veth pair                                           |
| `scripts/load_xdp.sh`        | Build, load, and pin the BPF program                                        |
| `scripts/make_plots.py`      | Render Fig. X and Fig. Y from raw CSVs                                      |
| `scripts/make_plot_contention_v2.py` | Render the contention figure                                        |
| `results/`                   | Raw per-rule CSVs and aggregated summaries                                  |

## Build environment

- Linux kernel ≥ 5.15 with `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`
- `clang` ≥ 12 (tested with clang 14)
- `libbpf-dev` ≥ 1.0 (tested with 1.4)
- `bpftool` ≥ 5.15
- Python 3.10 with `scapy` (specifically `scapy.contrib.gtp`)
- `gcc` (for the C harnesses)

On Ubuntu 22.04:

```bash
sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev gcc-multilib \
                    build-essential pkg-config linux-tools-common \
                    linux-tools-generic linux-tools-$(uname -r) \
                    iproute2 ethtool tcpdump python3 python3-scapy
```

## Reproducing the paper results

```bash
# Build BPF + harnesses
make
gcc -O2 -Wall -o test/bench_rule_update test/bench_rule_update.c -lbpf -lelf -lz
gcc -O2 -Wall -o test/bench_memory      test/bench_memory.c      -lbpf -lelf -lz
gcc -O2 -Wall -o test/gtpu_blast        test/gtpu_blast.c

# Bring up the testbed (isolated netns + veth + XDP)
sudo bash scripts/setup_netns.sh up
sudo bash scripts/load_xdp.sh up

# Start the control-plane stub
sudo python3 loader/agent.py &

# 1. Functional validation (Table III in the paper)
sudo ip netns exec upfns python3 test/send_gtpu.py --n 1000 --mix --teid 0x1000
curl -s http://127.0.0.1:9090/metrics

# 2. Rule-update latency across batch sizes (Table IV)
for n in 1 10 50 100 500 1000 2000 ; do
    sudo test/bench_rule_update $n results/clean_n${n}.csv
done

# 3. Zero-downtime under live traffic (Table V)
DURATION=10 TARGET_PPS=50000 N_RULES=100 bash test/zero_downtime.sh

# 4. Contention sweep — 5 repeats across rates × batch sizes
R=5 bash test/contention_sweep_repeated.sh

# 5. Render figures
python3 scripts/make_plots.py
python3 scripts/make_plot_contention_v2.py
```

## Headline empirical results (from the paper)

- **100-rule install in 0.52 ms** at the `bpf()` syscall level (no concurrent
  traffic)
- **Zero-downtime validated**: 63,018 G-PDU packets streamed during a 100-rule
  mid-stream installation, **0% packet loss**, per-rule p99 of 9.1 µs
- **Contention robustness**: across 60 measurements at four traffic rates
  (0 — 100k pps) × three batch sizes (100, 500, 1000), **1,576,690 packets,
  0 miss-classifications, p99 update latency bounded under 14 µs**
- **In-kernel observability**: Prometheus `/metrics` endpoint exposes nine
  per-stage counters with per-CPU aggregation

See `results/contention_agg.csv` and `results/clean_n*.csv` for the raw data.

## Limitations

This is a research prototype, not a production UPF. In particular:

- Only the uplink classification path is implemented in BPF; full
  PDR/FAR/QER/URR enforcement at the TC layer is sketched in the paper but
  not implemented here.
- Tested only on generic-XDP attached to a `veth` pair within a Xen VM;
  hardware-NIC validation on a 10 GbE NIC (e.g., Intel X520) is the principal
  outstanding item of future work.
- Control plane is a Python stub. A full PFCP stack on N4 is out of scope.

## License

Apache-2.0 (see `LICENSE`).

## Citing

If you use this code in academic work, please cite the paper:

```bibtex
@article{valia2026ebpf,
  title   = {eBPF-Driven Programmable Traffic Steering and In-Kernel
             Observability for 5G User Plane Functions: An Architectural
             Investigation},
  author  = {Valia, Shiva and Rathi, Vipin Kumar and Pathak, Sahil and
             Rajput, Nikhil Kumar},
  journal = {IEEE Access},
  year    = {2026}
}
```
