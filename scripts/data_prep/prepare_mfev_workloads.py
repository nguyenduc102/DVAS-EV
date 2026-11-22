#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from dbas_et.workloads_mfev import (
    load_raw_mfev,
    normalize_mfev_to_dbas,
    make_samples,
    summarize_workload,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", default="data/raw/mfev")
    parser.add_argument("--out-dir", default="data/processed/mfev")
    parser.add_argument("--tables-dir", default="outputs/tables")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--sizes", nargs="+", type=int, default=[5000, 10000, 50000])
    parser.add_argument("--valid-margin", type=float, default=1.10)
    parser.add_argument("--undercap-rate", type=float, default=0.025)
    args = parser.parse_args()

    raw = load_raw_mfev(args.raw_dir)
    print(f"[INFO] raw rows: {len(raw)}")

    norm = normalize_mfev_to_dbas(
        raw,
        seed=args.seed,
        valid_margin=args.valid_margin,
        undercap_rate=args.undercap_rate,
    )
    print(f"[INFO] normalized cleaned rows: {len(norm)}")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    full_path = out_dir / "mfev_full_normalized.csv"
    norm.to_csv(full_path, index=False)
    print(f"[OK] wrote full normalized workload -> {full_path}")

    sample_paths = make_samples(
        norm,
        sizes=args.sizes,
        out_dir=out_dir,
        seed=args.seed,
        prefix="mfev",
    )

    tables_dir = Path(args.tables_dir)
    tables_dir.mkdir(parents=True, exist_ok=True)

    summaries = []
    summaries.append(summarize_workload(norm, "mfev_full_normalized"))

    for n, p in sample_paths.items():
        df_n = pd.read_csv(p)
        summaries.append(summarize_workload(df_n, f"mfev_{n}"))

    summary_df = pd.DataFrame(summaries)
    summary_path = tables_dir / "mfev_workload_summary.csv"
    summary_df.to_csv(summary_path, index=False)
    print(f"[OK] wrote summary -> {summary_path}")

    print()
    print(summary_df.to_string(index=False))


if __name__ == "__main__":
    main()