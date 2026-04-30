#!/usr/bin/env python3
"""
Generate paper figures from raw measurement CSVs.

Produces two PDFs in results/:
  fig_ruleupdate_cdf.pdf   - empirical CDF of per-rule update latency for
                             representative batch sizes
  fig_ruleupdate_scaling.pdf - mean / p95 / p99 per-rule latency vs batch size N

Both figures use the data already collected in results/clean_n*.csv.
"""
import os
import sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "results")

# Stylistic defaults — IEEE-friendly: serif font, single column ~3.5in width
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


def load_clean(n):
    """Return a numpy array of per-rule update latencies (µs) for clean run N=n."""
    p = os.path.join(RESULTS, f"clean_n{n}.csv")
    if not os.path.exists(p):
        return None
    df = pd.read_csv(p)
    return df["update_us"].to_numpy()


def fig_cdf():
    fig, ax = plt.subplots(figsize=(3.5, 2.4))
    cases = [10, 100, 1000]
    colors = ["tab:blue", "tab:orange", "tab:green"]
    markers = ["o", "s", "^"]

    for n, c, m in zip(cases, colors, markers):
        x = load_clean(n)
        if x is None or len(x) == 0:
            continue
        xs = np.sort(x)
        ys = np.arange(1, len(xs) + 1) / len(xs)
        ax.plot(xs, ys, color=c, lw=1.5, label=f"$N={n}$ rules")

    ax.set_xlabel(r"Per-rule update latency ($\mu$s)")
    ax.set_ylabel("Empirical CDF")
    ax.set_xscale("log")
    ax.grid(True, which="both", linestyle=":", linewidth=0.5, alpha=0.7)
    ax.set_ylim(0, 1.01)
    ax.legend(loc="lower right", framealpha=0.9)
    ax.set_title("Rule-update latency distribution")
    fig.tight_layout(pad=0.4)

    out = os.path.join(RESULTS, "fig_ruleupdate_cdf.pdf")
    fig.savefig(out)
    fig.savefig(out.replace(".pdf", ".png"))
    print(f"  wrote {out}")
    plt.close(fig)


def fig_scaling():
    Ns, means, p50, p95, p99, mins, maxs = [], [], [], [], [], [], []
    for n in [1, 10, 50, 100, 500, 1000, 2000]:
        x = load_clean(n)
        if x is None or len(x) == 0:
            continue
        Ns.append(n)
        means.append(np.mean(x))
        p50.append(np.percentile(x, 50))
        p95.append(np.percentile(x, 95))
        p99.append(np.percentile(x, 99))
        mins.append(np.min(x))
        maxs.append(np.max(x))

    Ns = np.array(Ns)

    fig, ax = plt.subplots(figsize=(3.5, 2.6))
    ax.plot(Ns, means, "o-", color="tab:blue",   lw=1.5, ms=4.5, label="mean")
    ax.plot(Ns, p50,   "s--", color="tab:gray",  lw=1.2, ms=4.0, label="p50")
    ax.plot(Ns, p95,   "^-",  color="tab:orange",lw=1.5, ms=4.5, label="p95")
    ax.plot(Ns, p99,   "v-",  color="tab:red",   lw=1.5, ms=4.5, label="p99")

    ax.set_xscale("log")
    ax.set_xlabel(r"Batch size $N$ (rules per install)")
    ax.set_ylabel(r"Per-rule latency ($\mu$s)")
    ax.grid(True, which="both", linestyle=":", linewidth=0.5, alpha=0.7)
    ax.legend(loc="upper left", framealpha=0.9, ncol=2)
    ax.set_title("Per-rule update latency vs batch size")
    ax.set_ylim(bottom=0)
    fig.tight_layout(pad=0.4)

    out = os.path.join(RESULTS, "fig_ruleupdate_scaling.pdf")
    fig.savefig(out)
    fig.savefig(out.replace(".pdf", ".png"))
    print(f"  wrote {out}")
    plt.close(fig)


if __name__ == "__main__":
    print(f"reading CSVs from: {RESULTS}")
    fig_cdf()
    fig_scaling()
    print("done.")
