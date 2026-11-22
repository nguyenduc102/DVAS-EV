"""Regression workloads (ACN valid / original-cap / top-up vs unchanged legacy pipeline, MFEV valid).

Reuses the validated ``regression()`` of run_validation.py.
Outputs: <OUT>/regression_rows.csv (per row) and <OUT>/regression_checks.csv.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, write_csv, write_metadata  # noqa: E402

import run_validation as v  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=5000)
    a = ap.parse_args()
    write_metadata("regression_workloads")
    rows: list[dict] = []
    v.regression(rows, a.rows)
    write_csv(OUT / "regression_rows.csv", rows)
    write_csv(OUT / "regression_checks.csv", v.RESULTS)
    return 0 if all(r["pass"] for r in v.RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
