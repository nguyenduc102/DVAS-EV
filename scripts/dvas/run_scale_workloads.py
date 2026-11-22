"""Full-scale workflow outcomes with the quorum design (Fig. 3).

Runs the current DVAS-EV pipeline (DvasEnvironment, exact decimal tariff,
quorum verifiers in one process) on the same ACN-30k / MFEV-50k inputs that the
legacy single-SV figure used:

  ACN-30k  Valid | Original cap | Top-up (3,394 under-reserved rows)
  MFEV-50k Valid | Original cap | Top-up (1,242 under-reserved rows)

MFEV top-up rows carry no ``topup_delta_recommended`` column. The delta follows
the legacy harness fallback rule (scripts/benchmark_common.py):
    delta = max(0, 1.10 * expected_amount - preauth_limit)

Timings are ``timings_ms["total"]`` of settled sessions: local in-process
protocol-processing latency (same metric as the 5k regression), not the matched
loopback campaign (separate verifier processes) and not end-to-end charging.

Outputs (under $DVAS_OUT or outputs/):
  scale_workloads/scale_rows.csv      one row per session
  scale_workloads/scale_summary.csv   one row per workload/config (source of Fig. 3)
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, ROOT, write_csv, write_metadata  # noqa: E402

from dbas_et.dvas.profiles import PROFILES  # noqa: E402
from dbas_et.dvas.protocol import DvasEnvironment  # noqa: E402
from dbas_et.dvas.workload import acn_sessions, honest_amount, mfev_sessions, to_fixed6  # noqa: E402

ACN_DIR = ROOT / "data" / "acn" / "processed"
MFEV_DIR = ROOT / "data" / "processed" / "mfev" / "runner_fixed"

WORKLOADS = [
    # (dataset, scenario, path, loader, topup)
    ("ACN-30k", "Valid", ACN_DIR / "profile_valid_preauthorization_cached_acn_0p1_n30000_unique.csv", "acn", False),
    ("ACN-30k", "Original cap", ACN_DIR / "profile_original_cap_cached_acn_0p1_n30000_unique.csv", "acn", False),
    ("ACN-30k", "Top-up", ACN_DIR / "profile_undercap_topup_cached_acn_0p1_n30000_unique.csv", "acn", True),
    ("MFEV-50k", "Valid", MFEV_DIR / "mfev_50000_valid_fixed.csv", "mfev", False),
    ("MFEV-50k", "Original cap", MFEV_DIR / "mfev_50000_original_cap_fixed.csv", "mfev", False),
    ("MFEV-50k", "Top-up", MFEV_DIR / "mfev_50000_topup_cases_fixed.csv", "mfev", True),
]


def load(kind: str, path: Path, n: int | None, topup: bool):
    if kind == "acn":
        return acn_sessions(path, max_rows=n)
    specs = mfev_sessions(path, max_rows=n)
    if topup:
        specs = [replace(s, topup_delta=to_fixed6(max(Decimal(0), s.expected_amount * Decimal("1.10")
                                                       - s.preauth_limit)))
                 for s in specs]
    return specs


def pct(values: list[float], q: float) -> float:
    if not values:
        return float("nan")
    v = sorted(values)
    return v[min(len(v) - 1, max(0, int(round(q * (len(v) - 1)))))]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=None, help="limit rows per workload (smoke test)")
    ap.add_argument("--profile", default="C3")
    ap.add_argument("--quorum", default="2/3", help="comma list of t/n, e.g. 2/3,3/5")
    ap.add_argument("--only", default="", help="comma list of dataset names to run, e.g. ACN-30k")
    ap.add_argument("--scenario", default="", help="comma list of scenarios to run, e.g. Top-up")
    ap.add_argument("--acn-topup", default="", help="override the ACN-30k top-up input CSV")
    a = ap.parse_args()
    if a.acn_topup:
        for k, w in enumerate(WORKLOADS):
            if w[0] == "ACN-30k" and w[1] == "Top-up":
                WORKLOADS[k] = (w[0], w[1], (ROOT / a.acn_topup).resolve(), w[3], w[4])
    scen = {x.strip() for x in a.scenario.split(",") if x.strip()}
    out_dir = OUT / "scale_workloads"
    write_metadata("scale_workloads")
    only = {x.strip() for x in a.only.split(",") if x.strip()}
    rows: list[dict] = []
    summary: list[dict] = []
    for q in [x.strip() for x in a.quorum.split(",") if x.strip()]:
        t, n = (int(x) for x in q.split("/"))
        for dataset, scenario, path, kind, topup in WORKLOADS:
            if (only and dataset not in only) or (scen and scenario not in scen):
                continue
            specs = load(kind, path, a.rows, topup)
            env = DvasEnvironment(profile=PROFILES[a.profile], n=n, t=t)
            settled = exact = 0
            times: list[float] = []
            stages: dict[str, int] = {}
            t0 = time.perf_counter()
            for sp in specs:
                r = env.run(sp, topup=topup)
                honest = honest_amount(sp)
                ok_exact = bool(r.ok and r.captured == honest)
                settled += r.ok
                exact += ok_exact
                if r.ok:
                    times.append(r.timings_ms.get("total", 0.0))
                else:
                    stages[r.stage] = stages.get(r.stage, 0) + 1
                rows.append({"quorum": q, "dataset": dataset, "scenario": scenario, "row_index": sp.row_index,
                             "tid": sp.tid, "ok": r.ok, "stage": r.stage, "code": r.code[:120],
                             "captured": r.captured, "honest_amount": honest, "amount_exact": ok_exact,
                             "preauth_limit": sp.preauth_limit, "topup_delta": sp.topup_delta if topup else 0,
                             "total_ms": round(r.timings_ms.get("total", 0.0), 4)})
            el = time.perf_counter() - t0
            summary.append({"quorum": q, "profile": a.profile, "dataset": dataset, "scenario": scenario,
                            "sessions": len(specs), "settled": settled, "blocked": len(specs) - settled,
                            "amount_exact": exact, "blocked_by_stage": ";".join(f"{k}:{v}" for k, v in sorted(stages.items())),
                            "median_ms": round(statistics.median(times), 4) if times else None,
                            "p95_ms": round(pct(times, 0.95), 4) if times else None,
                            "wall_s": round(el, 1), "input": str(path.relative_to(ROOT))})
            print(f"[{q}] {dataset} {scenario}: {settled}/{len(specs)} settled, exact={exact}, "
                  f"median={summary[-1]['median_ms']} ms, p95={summary[-1]['p95_ms']} ms, {el:.1f}s", flush=True)
            write_csv(out_dir / "scale_summary.csv", summary)
    write_csv(out_dir / "scale_rows.csv", rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
