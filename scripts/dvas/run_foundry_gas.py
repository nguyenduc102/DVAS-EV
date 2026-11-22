"""Foundry tests + gas extraction -> <OUT>/solidity_gas.csv, <OUT>/raw/forge_output.txt, <OUT>/foundry_summary.csv."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, write_csv  # noqa: E402

import run_validation as v  # noqa: E402


def main() -> int:
    (OUT / "raw").mkdir(parents=True, exist_ok=True)
    v.forge_suite()
    write_csv(OUT / "foundry_summary.csv", v.RESULTS)
    return 0 if all(r["pass"] for r in v.RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
