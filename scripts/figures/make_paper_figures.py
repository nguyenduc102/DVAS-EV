#!/usr/bin/env python3
"""Draw the five result figures of the paper from the CSV files in results/.

    python scripts/figures/make_paper_figures.py [--results results] [--out outputs/figures]

  Fig. 2  fig_matched_latency_split   matched loopback campaign, median settlement time
          <- results/matched_campaign/summary_uncertainty.csv
  Fig. 3  fig_scale_stack_cdf         scale outcomes and in-process time CDFs
          <- results/scale/scale_summary.csv, results/scale/scale_rows.csv.gz
  Fig. 4  fig_phase_delta             per-component in-process time, ACN-30k
          <- results/quorum_tables/t3_rbc_timing.csv
  Fig. 5  fig_opening_views_heat      PAM-Proof vs row-level opening per disclosure view
          <- results/paper_artifact/pam_ablation.csv
  Fig. 6  fig_opening_bars            settlement-view openings, ablation and public libraries
          <- results/paper_artifact/pam_ablation.csv,
             results/library_baselines/oz_e9_check_summary.csv,
             results/library_baselines/sdjwt_bbs_e9_summary.csv

The script only reads results. It reruns no benchmark. Point --results at a fresh
output directory with the same layout to plot a new run.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
RES = ROOT / "results"
OUT = ROOT / "outputs" / "figures"

# ------------------------------------------------------------------ style
BLUE, ORANGE, AQUA, YELLOW = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
BLUE_BAND = "#e8f1fb"
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
GRAY_DARK = "#6f6e69"
CW = 3.45  # single-column width (in)

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["STIX Two Text", "STIXGeneral", "DejaVu Serif"],
    "mathtext.fontset": "stix", "font.size": 7.5, "axes.labelsize": 7.5,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "legend.fontsize": 7,
    "axes.edgecolor": INK2, "axes.linewidth": 0.6, "axes.labelcolor": INK,
    "xtick.color": INK2, "ytick.color": INK, "xtick.major.width": 0.6, "ytick.major.width": 0.6,
    "xtick.major.size": 2.2, "ytick.major.size": 2.2,
    "axes.spines.top": False, "axes.spines.right": False,
    "pdf.fonttype": 42, "ps.fonttype": 42,
})


def grid(ax, axis="y"):
    ax.grid(axis=axis, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)


def save(fig, stem):
    OUT.mkdir(parents=True, exist_ok=True)
    for ext, kw in (("pdf", {}), ("png", {"dpi": 400})):
        fig.savefig(OUT / f"{stem}.{ext}", facecolor="white", **kw)
    plt.close(fig)
    print(f"[OK] {OUT / stem}.pdf")


# ------------------------------------------------------------------ Fig. 2: matched settlement time
METHODS = {"FullTranscriptEscrow": ("Full-transcript escrow", AQUA),
           "FullEvidenceQuorum": ("Full-evidence quorum", ORANGE),
           "DVASSelectiveQuorum": ("DVAS-EV", BLUE)}
CATS = [("ACN", 2, 3), ("ACN", 3, 5), ("MFEV", 2, 3), ("MFEV", 3, 5)]
PROFILE_TITLES = {"C0": "Classical profile", "C3": "Hybrid post-quantum profile"}  # C0/C3: profile ids in the code


def matched_summary(metric):
    d = pd.read_csv(RES / "matched_campaign" / "summary_uncertainty.csv")
    d = d[(d.phase == "healthy") & (d.scenario == "healthy") & (d.metric == metric)]
    return {(r.method, r.profile, r.dataset, int(r.t), int(r.n)): r.median_of_run_medians for _, r in d.iterrows()}


def fig_matched_latency_split():
    E = matched_summary("elapsed_ms")
    Q = matched_summary("quorum_elapsed_ms")
    fig, axes = plt.subplots(1, 2, sharey=True, figsize=(CW, 1.94))
    w = 0.26
    for ax, pr in zip(axes, ("C0", "C3")):
        for i, k in enumerate(METHODS):
            col = METHODS[k][1]
            for j, (ds, t, n) in enumerate(CATS):
                tot, q = E[(k, pr, ds, t, n)], Q[(k, pr, ds, t, n)]
                x = j + (i - 1) * (w + 0.02)
                # solid lower part: local processing. Hatched upper part: quorum collection
                ax.bar(x, tot - q, w, color=col, edgecolor="white", linewidth=0.4, zorder=2)
                if q > 0:
                    ax.bar(x, q, w, bottom=tot - q, color=col, alpha=0.45, hatch="////", edgecolor=col,
                           linewidth=0.0, zorder=2)
        ax.set_xticks(range(4))
        ax.set_xticklabels([f"{ds}\n{t}-of-{n}" for ds, t, n in CATS], fontsize=6.5)
        ax.tick_params(axis="x", length=0, pad=2)
        ax.set_title(PROFILE_TITLES[pr], fontsize=7.3, pad=2, color=INK)
        ax.set_xlim(-0.5, 3.5)
        grid(ax)
    axes[0].set_ylabel("Median settlement time (ms)")
    axes[0].set_ylim(0, 7.5)
    methods = [Patch(color=c, label=lab) for lab, c in METHODS.values()]
    lg1 = fig.legend(handles=methods, loc="upper center", bbox_to_anchor=(0.555, 1.0), ncol=3, frameon=False,
                     fontsize=6.3, handlelength=1.0, handletextpad=0.3, columnspacing=0.9)
    lg1.get_texts()[2].set_fontweight("bold")
    segs = [Patch(facecolor="#7a7974", edgecolor="white", label="Local processing (solid, lower part)"),
            Patch(facecolor="#cfcec9", hatch="////", edgecolor="#7a7974", lw=0.0,
                  label="Quorum collection (hatched, upper part)")]
    fig.legend(handles=segs, loc="upper center", bbox_to_anchor=(0.545, 0.925), ncol=2, frameon=False,
               fontsize=6.3, handlelength=1.4, handletextpad=0.3, columnspacing=1.2)
    fig.add_artist(lg1)
    fig.subplots_adjust(left=0.12, right=0.995, top=0.76, bottom=0.165, wspace=0.07)
    save(fig, "fig_matched_latency_split")


# ------------------------------------------------------------------ Fig. 3: scale outcomes and CDFs
SCN = {"Valid": ("Valid", BLUE), "Original cap": ("Original hold (settled)", GRAY_DARK), "Top-up": ("Top-up", ORANGE)}
QLS = {"2/3": ("2-of-3", "-"), "3/5": ("3-of-5", (0, (4, 2)))}


def load_scale():
    s = pd.read_csv(RES / "scale" / "scale_summary.csv")
    rows_path = RES / "scale" / "scale_rows.csv.gz"
    rows = pd.read_csv(rows_path if rows_path.exists() else RES / "scale" / "scale_rows.csv")
    rows["ok"] = rows.ok.astype(str).str.lower() == "true"
    return s, rows[rows.ok]


def outcome_panel(ax, s):
    rows = []
    for ds in ("ACN-30k", "MFEV-50k"):
        for sc, lab in (("Valid", "Valid hold"), ("Original cap", "Original hold")):
            r = s[(s.dataset == ds) & (s.scenario == sc) & (s.quorum == "2/3")].iloc[0]
            top = s[(s.dataset == ds) & (s.scenario == "Top-up") & (s.quorum == "2/3")].iloc[0]
            rows.append((ds, lab, int(r.sessions), int(r.settled), int(r.blocked),
                         int(top.settled) if r.blocked else 0))
    y = np.array([3.4, 2.4, 1.0, 0.0])
    for yi, (ds, lab, n, ok, ref, topok) in zip(y, rows):
        ax.barh(yi, 100 * ok / n, 0.62, color=BLUE, edgecolor="white", linewidth=0.4, zorder=2)
        if ref:
            ax.barh(yi, 100 * ref / n, 0.62, left=100 * ok / n, color=ORANGE, hatch="////", edgecolor="white",
                    linewidth=0.4, zorder=2)
        txt = f"{ok:,} at hold + {ref:,} after top-up" if ref else f"{ok:,} / {n:,}"
        ax.text(2, yi, txt, va="center", fontsize=6.2, color="white", fontweight="bold")
    ax.set_yticks(y)
    ax.set_yticklabels([f"{r[0]}\n{r[1].lower()}" for r in rows], fontsize=6.4, linespacing=0.95)
    ax.tick_params(axis="y", length=0)
    ax.set_xlim(0, 100)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_ylim(-0.6, 4.0)
    ax.set_xlabel("(a) Share of sessions (%)")
    grid(ax, "x")
    ax.legend(handles=[Patch(color=BLUE, label="Settled at the hold"),
                       Patch(facecolor=ORANGE, hatch="////", edgecolor="white", label="Refused, then top-up")],
              loc="lower left", bbox_to_anchor=(0.0, 1.0), ncol=2, frameon=False, fontsize=6.0, handlelength=1.0,
              columnspacing=0.8, borderaxespad=0.1)


def fig_scale_stack_cdf():
    mk = {"Valid": "o", "Original cap": "s", "Top-up": "^"}  # markers keep scenarios apart in grayscale
    fig = plt.figure(figsize=(7.0, 2.05))
    gs = fig.add_gridspec(1, 3, width_ratios=[1.15, 1, 1], wspace=0.42)
    s, rows = load_scale()
    outcome_panel(fig.add_subplot(gs[0, 0]), s)
    a1 = fig.add_subplot(gs[0, 1])
    a2 = fig.add_subplot(gs[0, 2], sharey=a1, sharex=a1)
    for ax, ds, lab in ((a1, "ACN-30k", "(b) ACN-30k"), (a2, "MFEV-50k", "(c) MFEV-50k")):
        for sc, (_, col) in SCN.items():
            for qi, (q, (_, ls)) in enumerate(QLS.items()):
                x = np.sort(rows[(rows.dataset == ds) & (rows.quorum == q) & (rows.scenario == sc)].total_ms.values)
                y = np.arange(1, len(x) + 1) / len(x)
                fr = (0.15, 0.45, 0.75) if qi == 0 else (0.30, 0.60, 0.88)
                idx = [int(f * (len(x) - 1)) for f in fr]
                ax.plot(x, y, color=col, ls=ls, lw=1.15, marker=mk[sc], markevery=idx, ms=3.2,
                        mfc="white", mec=col, mew=0.8)
                p95 = x[int(round(0.95 * (len(x) - 1)))]
                ax.scatter(p95, 0.95, s=9, color=col, zorder=4, edgecolor="white", linewidth=0.3)
        ax.axhline(0.95, color=INK2, lw=0.4, ls=(0, (1, 2)))
        ax.text(3.02, 0.965, "P95", fontsize=5.8, color=INK2, va="bottom")
        ax.set_xlim(3.0, 6.0)
        ax.set_ylim(0, 1.02)
        ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
        ax.set_xlabel(f"{lab}: in-process time (ms)")
        grid(ax, "x")
        ax.grid(axis="y", color=GRID, lw=0.4)
    a1.set_ylabel("Cumulative fraction")
    plt.setp(a2.get_yticklabels(), visible=False)
    h1 = [Line2D([], [], color=c, lw=1.4, marker=mk[k], ms=3.4, mfc="white", mec=c, mew=0.8, label=lab)
          for k, (lab, c) in SCN.items()]
    h2 = [Line2D([], [], color=INK2, lw=1.2, ls=ls, label=lab) for lab, ls in QLS.values()]
    fig.legend(handles=h1, loc="upper left", bbox_to_anchor=(0.43, 1.0), ncol=3, frameon=False, fontsize=6.3,
               handlelength=2.0, columnspacing=0.9, handletextpad=0.3)
    fig.legend(handles=h2, loc="upper right", bbox_to_anchor=(0.99, 1.0), ncol=2, frameon=False, fontsize=6.3,
               handlelength=2.0, columnspacing=0.9, handletextpad=0.3)
    fig.subplots_adjust(left=0.105, right=0.99, top=0.85, bottom=0.215)
    save(fig, "fig_scale_stack_cdf")


# ------------------------------------------------------------------ Fig. 4: per-component time
PHASE_COL = {"Authorization": BLUE, "Session and receipt": ORANGE, "Verifier quorum": AQUA, "Contract release": YELLOW}
COMP = [("Authorization", "Commit root"), ("Authorization", "Authorization sign/open"),
        ("Authorization", "Authorize reserve"), ("Session and receipt", "Session open"),
        ("Session and receipt", "Receipt build/sign"), ("Session and receipt", "Protect private"),
        ("Session and receipt", "Receipt submit"), ("Verifier quorum", "SV quorum/RBC"),
        ("Contract release", "Release by RBC")]
SHORT = ["Commit", "Authorize", "Reserve", "Open session", "Sign receipt", "Encrypt", "Submit", "Quorum", "Release"]


def fig_phase_delta():
    t = pd.read_csv(RES / "quorum_tables" / "t3_rbc_timing.csv")

    def val(w, q, c):
        return t[(t.workload == w) & (t.quorum == q) & (t.component == c)]["median_ms"].iloc[0]

    y = np.arange(len(COMP))[::-1].astype(float)
    fig, (a1, a2) = plt.subplots(1, 2, sharey=True, figsize=(CW, 1.89), gridspec_kw={"width_ratios": [1.1, 1]})
    for ax in (a1, a2):
        for a, b in ((0, 3), (7, 8)):
            ax.axhspan(y[b - 1] - 0.5, y[a] + 0.5, color="#f4f3f0", lw=0, zorder=0)
    for yi, (ph, c) in zip(y, COMP):
        base = val("ACN-30k", "2-of-3", c)
        d = val("ACN-30k", "3-of-5", c) - base
        col = PHASE_COL[ph]
        a1.plot([0, base], [yi, yi], color=col, lw=1.0, zorder=2)
        a1.scatter(base, yi, s=20, color=col, edgecolor="white", linewidth=0.4, zorder=3)
        a1.text(base + 0.03, yi, f"{base:.2f}", va="center", fontsize=6.0, color=INK)
        a2.plot([0, d], [yi, yi], color=col, lw=1.4 if abs(d) > 0.2 else 1.0, zorder=2)
        a2.scatter(d, yi, s=20, color=col, edgecolor="white", linewidth=0.4, zorder=3)
        a2.text(max(d, 0) + 0.015, yi, ("0.00" if abs(d) < 0.005 else f"{d:+.2f}".replace("-", "−")), va="center",
                ha="left", fontsize=6.0, color=INK, fontweight="bold" if d > 0.2 else "normal")
    a1.set_xlim(0, 1.0)
    a1.set_xlabel("(a) 2-of-3 median (ms)")
    a2.axvline(0, color=INK2, lw=0.6)
    a2.set_xlim(-0.08, 0.5)
    a2.set_xticks([0, 0.2, 0.4])
    a2.set_xlabel("(b) Change at 3-of-5 (ms)")
    for ax in (a1, a2):
        grid(ax, "x")
        ax.tick_params(axis="y", length=0)
    a1.set_yticks(y)
    a1.set_yticklabels(SHORT, fontsize=6.8)
    tot_a, tot_b = val("ACN-30k", "2-of-3", "Total"), val("ACN-30k", "3-of-5", "Total")
    a2.text(0.98, 0.5, f"measured total\n{tot_a:.2f} to {tot_b:.2f} ms", transform=a2.transAxes, ha="right",
            va="center", fontsize=5.9, color=INK2, style="italic", linespacing=0.95)
    fig.subplots_adjust(left=0.2, right=0.98, top=0.985, bottom=0.205, wspace=0.08)
    save(fig, "fig_phase_delta")


# ------------------------------------------------------------------ Fig. 5: per-view reduction heatmap
VIEWS = [("authorization", "Authorization"), ("settlement", "Settlement"),
         ("dispute:tariff_mismatch", "Dispute: tariff"), ("dispute:time_window", "Dispute: time"),
         ("dispute:over_cap", "Dispute: over cap"), ("dispute:amount_exceeds_preauth", "Dispute: amount"),
         ("dispute:replay", "Dispute: replay")]


def fig_opening_views_heat():
    e = pd.read_csv(RES / "paper_artifact" / "pam_ablation.csv")
    metrics = [("disclosed_fields", "Fields"), ("sibling_hashes_median", "Sibling\nhashes"),
               ("total_bytes_median", "Size"), ("verify_us_median", "Verify\ntime")]
    M = np.zeros((len(VIEWS), len(metrics)))
    A = [[None] * len(metrics) for _ in VIEWS]
    for i, (key, _) in enumerate(VIEWS):
        for j, (col, _) in enumerate(metrics):
            pam = e[(e.reason == key) & (e.variant == "B3")][col].iloc[0]     # B3 = PAM-Proof
            row = e[(e.reason == key) & (e.variant == "B0-row")][col].iloc[0]  # B0-row = row-level opening
            M[i, j] = 100 * (1 - pam / row)
            A[i][j] = (pam, row)
    cmap = LinearSegmentedColormap.from_list("seqblue", ["#f3f7fc", "#a9c9ee", "#2a78d6", "#123f7a"])
    fig, ax = plt.subplots(figsize=(CW, 1.79))
    ax.imshow(M, cmap=cmap, vmin=0, vmax=100, aspect="auto")
    for i in range(len(VIEWS)):
        for j in range(len(metrics)):
            pam, row = A[i][j]
            fmt = (lambda v: f"{v:,.0f}") if j < 3 else (lambda v: f"{v:.0f}")
            ax.text(j, i - 0.13, f"−{M[i, j]:.0f}%", ha="center", va="center", fontsize=6.6,
                    color="white" if M[i, j] > 50 else INK, fontweight="bold")
            ax.text(j, i + 0.24, f"{fmt(pam)} / {fmt(row)}", ha="center", va="center", fontsize=5.4,
                    color="white" if M[i, j] > 50 else INK2)
    ax.set_xticks(range(len(metrics)))
    ax.set_xticklabels([m for _, m in metrics], fontsize=6.7, linespacing=0.95)
    ax.xaxis.tick_top()
    ax.set_yticks(range(len(VIEWS)))
    ax.set_yticklabels([v for _, v in VIEWS], fontsize=6.7)
    ax.tick_params(length=0)
    for sp in ax.spines.values():
        sp.set_visible(False)
    for x in np.arange(0.5, len(metrics) - 0.5):
        ax.axvline(x, color="white", lw=1.5)
    for yv in np.arange(0.5, len(VIEWS) - 0.5):
        ax.axhline(yv, color="white", lw=1.5)
    fig.subplots_adjust(left=0.28, right=0.985, top=0.855, bottom=0.015)
    save(fig, "fig_opening_views_heat")


# ------------------------------------------------------------------ Fig. 6: settlement-view openings
ABL = ["#9fb7d3", "#7d7c76", "#a3a29c", "#cfcdc7"]
LIB = ["#f2a57f", "#eb6834", "#f6c9b0"]
INCOMPLETE = 1060  # incomplete openings over all seven views (one omitted required field each)


def opening_rows():
    """label, group, colour, hatch, size (B), median verify (us), incomplete accepted, incomplete tested."""
    e = pd.read_csv(RES / "paper_artifact" / "pam_ablation.csv")
    e = e[e.reason == "settlement"].set_index("variant")
    oz = pd.read_csv(RES / "library_baselines" / "oz_e9_check_summary.csv")
    oz = oz[oz.view == "settlement"].set_index("variant")
    lib = pd.read_csv(RES / "library_baselines" / "sdjwt_bbs_e9_summary.csv")
    lib = lib[lib.view == "settlement"].set_index("variant")

    def pam(v):
        return float(e.loc[v, "total_bytes_median"]), float(e.loc[v, "verify_us_median"])

    def ext(t, v):
        return float(t.loc[v, "total_bytes_median"]), float(t.loc[v, "verify_us_median"])

    n = INCOMPLETE
    return [("PAM-Proof (ours)", "ours", BLUE, "", *pam("B3"), 0, n),
            ("Packed multiproof", "abl", ABL[0], "////", *pam("B2"), n, n),
            ("Separate paths", "abl", ABL[1], "", *pam("B1"), None, None),
            ("Row-level", "abl", ABL[2], "\\\\\\\\", *pam("B0-row"), None, None),
            ("Full disclosure", "abl", ABL[3], "....", *pam("B0-full"), None, None),
            ("OZ multiproof$^{\\dagger}$", "lib", LIB[0], "", *ext(oz, "OZ-compact"), n, n),
            ("OZ + check$^{\\dagger}$", "libchk", LIB[0], "\\\\\\\\", *ext(oz, "OZ-check"), 0, n),
            ("SD-JWT$^{\\dagger}$", "lib", LIB[1], "////", *ext(lib, "SD-JWT"), n, n),
            ("BBS$^{\\dagger}$", "lib", LIB[2], "xxxx", *ext(lib, "BBS"), n, n)]


def fig_opening_bars():
    M = opening_rows()
    Y = np.array([9.0, 7.6, 6.6, 5.6, 4.6, 3.0, 2.0, 1.0, 0.0])
    H = 0.68

    def hbar(ax, yi, val, mm, left=0):
        edge = INK2 if mm[1] != "ours" else BLUE
        ax.barh(yi, val, H, left=left, color=mm[2], hatch=mm[3], edgecolor=edge, linewidth=0.45, zorder=2)

    with plt.rc_context({"hatch.linewidth": 0.5}):
        fig, axes = plt.subplots(1, 3, sharey=True, figsize=(7.0, 1.92))
        for ax in axes:
            ax.axhspan(Y[0] - 0.5, Y[0] + 0.5, color=BLUE_BAND, lw=0, zorder=0)
        ax = axes[0]
        for yi, mm in zip(Y, M):
            hbar(ax, yi, mm[4], mm)
            txt = f"{mm[4]:,.0f}" + ("  (no proof)" if mm[0] == "Full disclosure" else "")
            ax.text(mm[4] + 80, yi, txt, va="center", fontsize=6.4, color=INK,
                    fontweight="bold" if mm[1] == "ours" else "normal")
        ax.set_xlim(0, 5400)
        ax.set_xticks(range(0, 5001, 1000))
        ax.set_xticklabels(["0", "1k", "2k", "3k", "4k", "5k"])
        ax.set_xlabel("(a) Settlement opening size (bytes)")
        ax = axes[1]
        for yi, mm in zip(Y, M):
            hbar(ax, yi, mm[5], mm)
            txt = f"{mm[5]:,.1f}" if mm[5] < 1000 else f"{mm[5]/1000:,.2f}k"
            ax.text(mm[5] * 1.15, yi, txt, va="center", fontsize=6.4, color=INK,
                    fontweight="bold" if mm[1] == "ours" else "normal")
        ax.set_xscale("log")
        ax.set_xlim(10, 4e6)
        ax.set_xticks([10, 1e2, 1e3, 1e4, 1e5, 1e6])
        ax.set_xticklabels(["10", "$10^2$", "$10^3$", "$10^4$", "$10^5$", "$10^6$"])
        ax.set_xlabel(r"(b) Median verification time ($\mu$s, log scale)")
        ax = axes[2]
        for yi, mm in zip(Y, M):
            if mm[6] is None:
                ax.text(3, yi, "n/a  (no required-field set)", va="center", fontsize=6.0, color=INK2, style="italic")
                continue
            share = 100 * mm[6] / mm[7]
            if share == 0:
                ours = mm[1] == "ours"
                ax.text(3, yi, "✓", va="center", fontsize=8.5, color=BLUE if ours else INK2,
                        fontfamily="DejaVu Sans", fontweight="bold")
                ax.text(12, yi, "0/1,060 accepted (all rejected)", va="center", fontsize=6.5 if ours else 6.2,
                        color=INK, fontweight="bold" if ours else "normal")
            else:
                hbar(ax, yi, share, mm)
                ax.text(share + 3, yi, "✗", va="center", fontsize=7.5, color=INK2, fontfamily="DejaVu Sans")
                ax.text(share + 11, yi, f"{mm[6]:,}/{mm[7]:,}", va="center", fontsize=6.2, color=INK)
        ax.set_xlim(0, 150)
        ax.set_xticks([0, 25, 50, 75, 100])
        ax.set_xlabel("(c) Incomplete openings accepted (%)")
        for ax in axes:
            grid(ax, "x")
            ax.tick_params(axis="y", length=0)
            ax.set_ylim(-0.6, 9.6)
            for yy in (3.75, 8.3):
                ax.axhline(yy, color=GRID, lw=0.6, zorder=1)
        axes[0].set_yticks(Y)
        axes[0].set_yticklabels([mm[0] for mm in M], fontsize=6.8)
        axes[0].get_yticklabels()[0].set_fontweight("bold")
        axes[0].text(-0.47, 6.1, "Ablation", transform=axes[0].get_yaxis_transform(), rotation=90, ha="center",
                     va="center", fontsize=6.4, color=INK2, style="italic")
        axes[0].text(-0.47, 1.5, "Libraries", transform=axes[0].get_yaxis_transform(), rotation=90, ha="center",
                     va="center", fontsize=6.4, color=INK2, style="italic")
        fig.subplots_adjust(left=0.16, right=0.995, top=0.985, bottom=0.215, wspace=0.1)
        save(fig, "fig_opening_bars")


FIGURES = {"2": fig_matched_latency_split, "3": fig_scale_stack_cdf, "4": fig_phase_delta,
           "5": fig_opening_views_heat, "6": fig_opening_bars}


def main() -> None:
    global RES, OUT
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", type=Path, default=RES, help="results directory (default: results/)")
    ap.add_argument("--out", type=Path, default=OUT, help="output directory (default: outputs/figures/)")
    ap.add_argument("--only", choices=sorted(FIGURES), nargs="*", help="figure numbers to draw (default: all)")
    a = ap.parse_args()
    RES, OUT = a.results.resolve(), a.out.resolve()
    for k in a.only or sorted(FIGURES):
        FIGURES[k]()


if __name__ == "__main__":
    main()
