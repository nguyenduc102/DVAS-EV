"""Paper figures from generated CSVs (no hard-coded results) -> <OUT>/figures/*.{pdf,svg,png}.

Figure 1  PAM decomposition (settlement predicate): disclosed fields, bytes split
          into disclosed values + authentication proof, verification time.
Figure 2  Quorum cost/security trade-off: critical-path latency, RBC size, gas
          (separate panels; never a dual axis).
Figure 3  Hybrid-PQ overhead (2-of-3): local latency and artifact sizes.

Palette: reference categorical slots 1-3 (#2a78d6, #eb6834, #1baf7a; documented
as validated for all pairs in light mode) + neutral gray for the legacy system.
Every bar carries a direct value label (placed above the P95 whisker where one
is drawn); the same numbers are in tables/*.csv.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT  # noqa: E402
from make_paper_artifact_tables import gas_for  # noqa: E402

S1, S2, S3, NEUTRAL = "#2a78d6", "#eb6834", "#1baf7a", "#8a8984"
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"
F = OUT / "figures"

plt.rcParams.update({
    "font.size": 9, "axes.titlesize": 9.5, "axes.labelsize": 9, "axes.edgecolor": MUTED, "axes.labelcolor": INK,
    "xtick.color": MUTED, "ytick.color": MUTED, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "axes.grid.axis": "y", "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "figure.facecolor": "white", "savefig.facecolor": "white", "pdf.fonttype": 42, "svg.fonttype": "none",
})
NL = "\n"


def rd(name: str) -> list[dict]:
    return list(csv.DictReader(open(OUT / name, encoding="utf-8")))


def save(fig, name: str) -> None:
    F.mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "svg", "png"):
        fig.savefig(F / f"{name}.{ext}", dpi=300 if ext == "png" else None, bbox_inches="tight")
    plt.close(fig)


def label_bars(ax, bars, fmt="{:.0f}", values=None, tops=None):
    """Direct value labels; ``tops`` places each label above its P95 whisker instead of the bar."""
    vals = values if values is not None else [b.get_height() for b in bars]
    ys = tops if tops is not None else [b.get_y() + b.get_height() for b in bars]
    for b, v, y in zip(bars, vals, ys):
        ax.annotate(fmt.format(v), (b.get_x() + b.get_width() / 2, y), xytext=(0, 2), textcoords="offset points",
                    ha="center", va="bottom", fontsize=7.5, color=INK)


def whisker(ax, x, med, p95):
    ax.errorbar(x, med, yerr=[[0] * len(med), [p - m for p, m in zip(p95, med)]], fmt="none", ecolor=MUTED,
                elinewidth=1, capsize=3)


def fig1() -> None:
    order = ["B0-full", "B0-row", "B1", "B2", "B3"]
    rows = sorted((r for r in rd("pam_ablation_updated.csv") if r["reason"] == "settlement" and r["row_type"] == "variant"),
                  key=lambda r: order.index(r["variant"]))
    x = list(range(len(rows)))
    names = [f"B0-full{NL}all fields", f"B0-row{NL}row-level", f"B1{NL}indep. paths", f"B2{NL}multiproof",
             f"B3{NL}PAM"]
    fig, axs = plt.subplots(1, 3, figsize=(11.5, 3.5), constrained_layout=True)
    b = axs[0].bar(x, [float(r["semantic_disclosure_fields"]) for r in rows], color=S1, width=0.62)
    label_bars(axs[0], b)
    axs[0].set_title("(a) Disclosed committed fields")
    axs[0].set_ylabel("fields")
    val = [float(r["disclosed_value_bytes"]) for r in rows]
    prf = [float(r["auth_proof_bytes"]) for r in rows]
    axs[1].bar(x, val, color=S1, width=0.62, label="disclosed values", edgecolor="white", linewidth=1)
    b2 = axs[1].bar(x, prf, bottom=val, color=S2, width=0.62, label="authentication (sibling hashes)",
                    edgecolor="white", linewidth=1)
    tot = [v + p for v, p in zip(val, prf)]
    label_bars(axs[1], b2, values=tot)
    axs[1].set_ylim(top=max(tot) * 1.12)
    axs[1].set_title("(b) Opening size (values + proof)")
    axs[1].set_ylabel("bytes")
    axs[1].legend(frameon=False, fontsize=7.5, loc="upper right")
    med = [float(r["verify_us_median"]) for r in rows]
    p95 = [float(r["verify_us_p95"]) for r in rows]
    b3 = axs[2].bar(x, med, color=S1, width=0.62)
    whisker(axs[2], x, med, p95)
    label_bars(axs[2], b3, "{:.0f}", tops=p95)
    axs[2].set_ylim(top=max(p95) * 1.45)
    axs[2].set_title("(c) Verification time (median, P95 whisker)")
    axs[2].set_ylabel("µs")
    inc = {r["variant"]: f"{r['incomplete_authentic_openings_accepted']}/{r['incomplete_authentic_openings_tested']}"
           for r in rows if r["incomplete_authentic_openings_tested"]}
    axs[2].annotate(f"incomplete authentic openings accepted{NL}B2: {inc.get('B2')}    B3: {inc.get('B3')}",
                    xy=(0.98, 0.98), xycoords="axes fraction", va="top", ha="right", fontsize=7.5, color=INK)
    for ax in axs:
        ax.set_xticks(x, names, fontsize=7.5)
    fig.suptitle("PAM decomposition (settlement predicate; B3 = B2 + predicate-completeness check): "
                 "selection = B0→B1, packing = B1→B2, completeness = B2→B3 (0 bytes)", fontsize=9.5, color=INK)
    save(fig, "fig1_pam_decomposition")


def fig2() -> None:
    qc = rd("quorum_cost.csv")
    labels = [f"legacy{NL}single SV" if r["config"].startswith("legacy") else r["config"].replace("DVAS-EV ", f"DVAS{NL}")
              for r in qc]
    colors = [NEUTRAL if r["config"].startswith("legacy") else S1 for r in qc]
    x = list(range(len(qc)))
    fig, axs = plt.subplots(1, 3, figsize=(11.5, 3.6), constrained_layout=True)
    med = [float(r["critical_path_ms_median"]) for r in qc]
    p95 = [float(r["critical_path_ms_p95"]) for r in qc]
    b = axs[0].bar(x, med, color=colors, width=0.6)
    whisker(axs[0], x, med, p95)
    label_bars(axs[0], b, "{:.2f}", tops=p95)
    axs[0].set_ylim(top=max(p95) * 1.15)
    axs[0].set_title(f"(a) Verification critical path{NL}(median, P95 whisker)")
    axs[0].set_ylabel("ms (local processing)")
    b = axs[1].bar(x, [float(r["rbc_bytes_median"]) for r in qc], color=colors, width=0.6)
    label_bars(axs[1], b)
    axs[1].set_title(f"(b) Settlement certificate size{NL}(legacy = JSON, DVAS = canonical binary)")
    axs[1].set_ylabel("bytes")
    b = axs[2].bar(x, [float(gas_for(r["config"])) for r in qc], color=colors, width=0.6)
    label_bars(axs[2], b, "{:,.0f}")
    axs[2].yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:,.0f}"))
    axs[2].set_title(f"(c) Settlement call gas{NL}(gasleft() delta, Foundry)")
    axs[2].set_ylabel("gas")
    for ax in axs:
        ax.set_xticks(x, labels, fontsize=7.5)
    fig.text(0.5, -0.05, "Fault tolerance (t-of-n): no incorrect settlement with fewer than t malicious verifiers; "
             "settlement needs t available honest verifiers (up to n-t unavailable).  Legacy single SV and 1-of-1 tolerate neither.",
             ha="center", fontsize=7.5, color=MUTED)
    save(fig, "fig2_quorum_tradeoff")


def fig3() -> None:
    pq = [r for r in rd("pq_ablation.csv") if r["config"] == "2-of-3"]
    names = {"C0": f"C0{NL}classical", "C1": f"C1{NL}ML-DSA auth", "C2": f"C2{NL}ML-KEM evidence", "C3": f"C3{NL}hybrid",
             "C4": f"C4{NL}hybrid +{NL}ML-DSA attest."}
    x = list(range(len(pq)))
    fig, axs = plt.subplots(1, 2, figsize=(11.5, 3.6), constrained_layout=True)
    med = [float(r["total_ms_median"]) for r in pq]
    p95 = [float(r["total_ms_p95"]) for r in pq]
    b = axs[0].bar(x, med, color=S1, width=0.6)
    whisker(axs[0], x, med, p95)
    label_bars(axs[0], b, "{:.2f}", tops=p95)
    axs[0].set_ylim(top=max(p95) * 1.15)
    axs[0].set_title(f"(a) Local protocol-processing latency per session{NL}(2-of-3, median, P95 whisker)")
    axs[0].set_ylabel("ms")
    axs[0].set_xticks(x, [names[r["profile"]] for r in pq], fontsize=7.5)
    series = [("private evidence envelope", "private_envelope_bytes_median", S1),
              ("quorum RBC", "rbc_bytes_median", S2), ("user authorization signature", "auth_sig_bytes", S3)]
    w = 0.26
    for i, (lab, key, col) in enumerate(series):
        bb = axs[1].bar([xx + (i - 1) * w for xx in x], [float(r[key]) for r in pq], width=w - 0.02, color=col, label=lab)
        label_bars(axs[1], bb, "{:.0f}")
    axs[1].set_yscale("log")
    axs[1].set_ylim(top=max(float(r["rbc_bytes_median"]) for r in pq) * 12)
    axs[1].set_title("(b) Artifact sizes (2-of-3, log scale)")
    axs[1].set_ylabel("bytes")
    axs[1].set_xticks(x, [names[r["profile"]] for r in pq], fontsize=7.5)
    axs[1].legend(frameon=False, fontsize=7.5, loc="upper left", ncol=3)
    save(fig, "fig3_pq_overhead")


def main() -> int:
    fig1()
    fig2()
    fig3()
    print("wrote", F)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
