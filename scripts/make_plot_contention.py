#!/usr/bin/env python3
"""
Build clean contention figure + summary table from contention_repeats_raw.csv
(5 repeats per (rate, N) cell). Use median across repeats — robust to
single-event preemption outliers on the shared VM.
"""
import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "results")

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 9,
    "axes.titlesize": 10,
    "axes.labelsize": 9,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "legend.fontsize": 8,
    "figure.dpi": 200,
})


def main():
    df = pd.read_csv(os.path.join(RESULTS, "contention_repeats_raw.csv"))
    print("rows:", len(df))
    print("packets sent total:", df["blast_sent"].sum())
    print("packets miss total:", df["miss_d"].sum())
    print("packets hit  total:", df["hit_d"].sum())

    keys = ["target_pps", "n_rules"]
    metric_cols = ["total_ms", "mean_us", "p50_us", "p95_us", "p99_us"]

    agg = (df.groupby(keys)[metric_cols]
             .agg(["median", "min", "max"])
             .reset_index())
    agg.columns = ["target_pps", "n_rules"] + [
        f"{a}_{b}" for a, b in agg.columns.tolist()[2:]
    ]
    out_csv = os.path.join(RESULTS, "contention_agg.csv")
    agg.to_csv(out_csv, index=False)
    print(f"\nwrote {out_csv}\n")
    print(agg.to_string(index=False))

    # --- plot: median p50 / p95 / p99 across rates, faceted by N -----------
    rates = sorted(df["target_pps"].unique())
    Ns    = sorted(df["n_rules"].unique())
    width = 0.27
    x = np.arange(len(rates))

    fig, ax = plt.subplots(figsize=(3.5, 2.6))
    colors = {"100": "tab:blue", "500": "tab:orange", "1000": "tab:green"}

    for i, n in enumerate(Ns):
        sub = df[df["n_rules"] == n].sort_values("target_pps")
        med = sub.groupby("target_pps")["p99_us"].median().reindex(rates).values
        med50 = sub.groupby("target_pps")["p50_us"].median().reindex(rates).values
        ax.bar(x + (i - 1) * width, med,
               width=width * 0.95, color=colors[str(n)],
               alpha=0.85, edgecolor="black", linewidth=0.4,
               label=f"N={n} (p99)")
        ax.plot(x + (i - 1) * width, med50, "kx", ms=5, mew=1.0)

    ax.set_xticks(x)
    ax.set_xticklabels([f"{r//1000}k" if r else "0" for r in rates])
    ax.set_xlabel("Concurrent traffic rate (pps)")
    ax.set_ylabel(r"Per-rule update latency ($\mu$s)")
    ax.set_title(r"Rule-update tail vs concurrent load (median of 5 runs)")
    ax.grid(True, axis="y", linestyle=":", linewidth=0.5, alpha=0.7)
    ax.legend(loc="upper left", framealpha=0.9, ncol=3)
    fig.text(0.5, -0.02, "(black ×) p50; bars are p99",
             ha="center", fontsize=7, color="dimgray")

    fig.tight_layout(pad=0.4)
    out = os.path.join(RESULTS, "fig_contention.pdf")
    fig.savefig(out, bbox_inches="tight")
    fig.savefig(out.replace(".pdf", ".png"), bbox_inches="tight")
    print(f"\nwrote {out}")

    # --- a one-line summary used in the LaTeX paragraph -----------------
    print("\n=== headline numbers (medians) ===")
    for r in rates:
        for n in [100, 500, 1000]:
            sub = df[(df.target_pps == r) & (df.n_rules == n)]
            if len(sub):
                print(f"  rate={r:>6} pps, N={n:>4}: total={sub.total_ms.median():.3f} ms, "
                      f"p50={sub.p50_us.median():.2f} µs, "
                      f"p95={sub.p95_us.median():.2f} µs, "
                      f"p99={sub.p99_us.median():.2f} µs")
    total_packets = int(df["blast_sent"].sum())
    total_loss    = int(df["miss_d"].sum())
    print(f"\n  ACROSS ALL 60 RUNS: {total_packets:,} packets sent, "
          f"{total_loss} miss-classifications, "
          f"loss = {100.0 * total_loss / max(1,total_packets):.4f}%")


if __name__ == "__main__":
    main()
