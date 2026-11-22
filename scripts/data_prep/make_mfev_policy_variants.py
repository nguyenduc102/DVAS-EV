#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def make_variants(n: int, in_dir: Path, out_dir: Path) -> None:
    src = in_dir / f"mfev_{n}.csv"
    if not src.exists():
        raise FileNotFoundError(f"Missing input file: {src}")

    df = pd.read_csv(src)

    required = [
        "preauth_limit_t",
        "preauth_limit_valid",
        "preauth_limit_original",
        "is_undercap_case",
    ]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns in {src}: {missing}")

    out_dir.mkdir(parents=True, exist_ok=True)

    # 1) Valid policy: enough preauthorization, every session settles.
    valid = df.copy()
    valid["preauth_limit_t"] = valid["preauth_limit_valid"].astype(float)
    valid_path = out_dir / f"mfev_{n}_policy_valid.csv"
    valid.to_csv(valid_path, index=False)

    # 2) Original-cap policy: under-cap sessions are blocked unless topped up.
    original = df.copy()
    original["preauth_limit_t"] = original["preauth_limit_original"].astype(float)
    original_path = out_dir / f"mfev_{n}_policy_original_cap.csv"
    original.to_csv(original_path, index=False)

    # 3) Top-up cases only: subset where original cap is insufficient.
    topup = original[original["is_undercap_case"].astype(bool)].copy()
    topup_path = out_dir / f"mfev_{n}_policy_topup_cases.csv"
    topup.to_csv(topup_path, index=False)

    print(f"[OK] N={n}")
    print(f"  valid:        {valid_path} rows={len(valid)}")
    print(f"  original-cap: {original_path} rows={len(original)}")
    print(f"  top-up cases: {topup_path} rows={len(topup)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in-dir", default="data/processed/mfev")
    parser.add_argument("--out-dir", default="data/processed/mfev/policy_variants")
    parser.add_argument("--sizes", nargs="+", type=int, default=[5000, 10000, 50000])
    args = parser.parse_args()

    in_dir = Path(args.in_dir)
    out_dir = Path(args.out_dir)

    for n in args.sizes:
        make_variants(n, in_dir, out_dir)


if __name__ == "__main__":
    main()