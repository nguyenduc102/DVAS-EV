"""Formal-property checks A-D at workload scale -> outputs/formal_properties_results.csv."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, write_csv, write_metadata  # noqa: E402

from dbas_et.dvas.formal_checks import build_contexts, run_all  # noqa: E402
from dbas_et.dvas.workload import acn_sessions, mfev_sessions  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--acn", type=int, default=20)
    ap.add_argument("--mfev", type=int, default=10)
    ap.add_argument("--seed", type=int, default=20261006)
    ap.add_argument("--scale", type=int, default=2)
    a = ap.parse_args()
    write_metadata("formal_properties")
    ctx = build_contexts(acn_sessions(max_rows=a.acn) + mfev_sessions(max_rows=a.mfev))
    rows = run_all(ctx, seed=a.seed, scale=a.scale)
    for r in rows:
        r["contexts"] = len(ctx)
        r["seed"] = a.seed
    write_csv(OUT / "formal_properties_results.csv", rows)
    agg: dict[str, list[int]] = {}
    for r in rows:
        t = agg.setdefault(r["property"], [0, 0])
        t[0] += r["trials"]; t[1] += r["passed"]
    for k, (t, p) in agg.items():
        print(f"{k:28s} {p}/{t} {'HOLDS' if p == t else 'VIOLATED'}")
    return 0 if all(r["holds"] for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
