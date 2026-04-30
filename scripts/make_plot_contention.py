#!/usr/bin/env python3
"""
Generate fig_contention.pdf from contention_sweep.csv.

Shows mean / p95 / p99 per-rule update latency for batch sizes N ∈ {100, 500, 1000}
at four concurrent traffic rates (0, 10k, 50k, 100k pps).
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
    df = pd.read_csv(os.path.join(RESULTS, "contention_sweep.csv"))
    fig, ax = plt.subplots(figsize=(3.5, 2.6))
    rates = sorted(df["target_pps"].unique())
    Ns    = sorted(df["n_rules"].unique())
    width = 0.25
    x = np.arange(len(rates))

    colors = {"100": "tab:blue", "500": "tab:orange", "1000": "tab:green"}
    for i, n in enumerate(Ns):
        sub = df[df["n_rules"] == n].sort_values("target_pps")
        # plot p99 as bars, p50 as a dot inside
        ax.bar(x + (i - 1) * width, sub["p99_us"].values,
               width=width * 0.95, color=colors[str(n)],
               alpha=0.85, edgecolor="black", linewidth=0.4,
               label=f"N={n} (p99)")
        ax.plot(x + (i - 1) * width, sub["p50_us"].values,
                "kx", ms=5, mew=1.0)

    ax.set_xticks(x)
    ax.set_xticklabels([f"{r//1000}k" if r else "0" for r in rates])
    ax.set_xlabel("Concurrent traffic rate (pps)")
    ax.set_ylabel(r"Per-rule update latency ($\mu$s)")
    ax.set_title(r"Rule-update tail vs concurrent load")
    ax.grid(True, axis="y", linestyle=":", linewidth=0.5, alpha=0.7)
    ax.legend(loc="upper left", framealpha=0.9, ncol=3)
    fig.text(0.5, -0.02, "(black ×) p50; bars are p99",
             ha="center", fontsize=7, color="dimgray")

    fig.tight_layout(pad=0.4)
    out = os.path.join(RESULTS, "fig_contention.pdf")
    fig.savefig(out, bbox_inches="tight")
    fig.savefig(out.replace(".pdf", ".png"), bbox_inches="tight")
    print("wrote", out)


if __name__ == "__main__":
    main()
