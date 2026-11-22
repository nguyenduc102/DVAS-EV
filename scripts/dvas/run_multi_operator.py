"""Multi-operator scenario.

Workload: ACN-Data (Caltech) + MFEV (two real CPO operator codes) sessions in
one registry/ledger with a 3-verifier cluster run by three verifier operators.

Scenario mapping (documented, not dataset facts):
  CPO (foreign operator):  ACN OF_CALTECH -> OP_A, MFEV OF_6b86b273 -> OP_B,
                           MFEV OF_5feceb66 -> OP_C   (dataset operator codes, relabelled)
  eMSP (home operator):    OP_{A,B,C} chosen by sha256(user_id) mod 3
Physical values (energy, timestamps, durations) come unchanged from the rows.

Outputs: outputs/multi_operator_results.csv (per session),
         outputs/multi_operator_summary.csv  (home x CPO matrix)
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, write_csv, write_metadata  # noqa: E402

from dbas_et.dvas.profiles import PROFILES  # noqa: E402
from dbas_et.dvas.protocol import DvasEnvironment  # noqa: E402
from dbas_et.dvas.registry import Role  # noqa: E402
from dbas_et.dvas.workload import acn_sessions, assign_operators, honest_amount, mfev_sessions  # noqa: E402

CPO_MAP = {"OF_CALTECH": "OP_A", "OF_6b86b273": "OP_B", "OF_5feceb66": "OP_C"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--acn", type=int, default=1000)
    ap.add_argument("--mfev", type=int, default=2000)
    ap.add_argument("--profile", default="C3")
    args = ap.parse_args()
    write_metadata("multi_operator")
    specs = assign_operators(acn_sessions(max_rows=args.acn) + mfev_sessions(max_rows=args.mfev), CPO_MAP)
    env = DvasEnvironment(profile=PROFILES[args.profile])
    rows = []
    for sp in specs:
        r = env.run(sp)
        rows.append({"source": sp.source, "row_index": sp.row_index, "tid": sp.tid, "home_operator": sp.home_operator,
                     "cpo": sp.foreign_operator, "cross_domain": sp.home_operator != sp.foreign_operator,
                     "ok": r.ok, "stage": r.stage, "code": r.code, "captured": r.captured,
                     "expected": honest_amount(sp), "amount_exact": r.captured == honest_amount(sp),
                     "total_ms": round(r.timings_ms.get("total", 0), 4), "operator_assignment": sp.operator_assignment})
    write_csv(OUT / "multi_operator_results.csv", rows)
    m = defaultdict(Counter)
    for r in rows:
        k = (r["home_operator"], r["cpo"])
        m[k]["sessions"] += 1
        m[k]["settled"] += r["ok"]
        m[k]["amount_exact"] += bool(r["amount_exact"])
    summ = [{"home_operator": h, "cpo": c, "cross_domain": h != c, **dict(v)} for (h, c), v in sorted(m.items())]
    reg = env.registry
    summ.append({"home_operator": "REGISTRY", "cpo": "",
                 "users": len(list(reg.entities(Role.USER))), "stations": len(list(reg.entities(Role.STATION))),
                 "meters": len(list(reg.entities(Role.METER))), "verifiers": len(list(reg.entities(Role.VERIFIER))),
                 "verifier_operators": len({reg.operator_of(v) for v in reg.entities(Role.VERIFIER)})})
    write_csv(OUT / "multi_operator_summary.csv", summ)
    for s in summ:
        print(s)
    tot = sum(r["ok"] for r in rows)
    print(f"settled {tot}/{len(rows)}; cross-domain {sum(r['cross_domain'] for r in rows)}")
    return 0 if tot == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
