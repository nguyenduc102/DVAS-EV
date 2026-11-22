"""Quorum fault-tolerance matrix -> outputs/quorum_fault_matrix.csv.

For each configuration (t-of-n), number m of COLLUDING malicious verifiers
(SV1..SVm, identical behaviour) and number o of OFFLINE verifiers (last o), three
adversarial goals are run on --rows ACN sessions:

  inflate_valid      valid delivery; malicious verifiers sign capture = hold
  approve_invalid    over-cap delivery (cap committed 0.5 kWh below delivery, amount
                     inside the hold); malicious verifiers approve without checking
  over_hold          valid delivery; malicious verifiers sign capture = hold + 1e-6

Outcome per session: CORRECT (honest result: correct amount settled, or invalid
delivery refused), INCORRECT_SETTLED (semantic decision bypassed),
NO_SETTLEMENT (liveness failure on a valid delivery).

Expected trust boundary:
  m <  t and n-m-o >= t : CORRECT
  m <  t and n-m-o <  t : NO_SETTLEMENT on valid deliveries (never INCORRECT)
  m >= t                : semantic quorum can be bypassed (inflate/approve) but
                          SettleSC public bounds still refuse over_hold.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, write_csv, write_metadata  # noqa: E402

from dbas_et.dvas.attacks import unique  # noqa: E402
from dbas_et.dvas.profiles import PROFILES  # noqa: E402
from dbas_et.dvas.protocol import DvasEnvironment  # noqa: E402
from dbas_et.dvas.workload import acn_sessions, honest_amount  # noqa: E402

GOALS = {"inflate_valid": "inflate", "approve_invalid": "approve_all", "over_hold": "over_hold"}


def scenarios(full: bool):
    out = [(3, 2, m, o) for m, o in [(0, 0), (1, 0), (2, 0), (0, 1), (0, 2), (1, 1), (3, 0)]]
    if full:
        out += [(5, 3, m, o) for m, o in [(0, 0), (1, 0), (2, 0), (3, 0), (0, 1), (0, 2), (0, 3), (2, 1), (1, 2)]]
    return out


def expected(t: int, n: int, m: int, o: int, goal: str) -> str:
    honest_up = n - m - o
    if m >= t:
        return "PUBLIC_BOUND_REFUSES" if goal == "over_hold" else "SEMANTIC_BYPASS_POSSIBLE"
    if goal == "approve_invalid":
        return "CORRECT"  # refusal is the correct outcome, needs no liveness
    return "CORRECT" if honest_up >= t else "NO_SETTLEMENT"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=30)
    ap.add_argument("--no-3of5", action="store_true")
    ap.add_argument("--profile", default="C3")
    ap.add_argument("--out", default=str(OUT / "quorum_fault_matrix.csv"))
    a = ap.parse_args()
    write_metadata("quorum_fault_matrix")
    specs = acn_sessions(max_rows=a.rows)
    rows = []
    for n, t, m, o in scenarios(not a.no_3of5):
        for goal, beh in GOALS.items():
            behaviors = {f"SV{i}": beh for i in range(1, m + 1)}
            behaviors.update({f"SV{i}": "offline" for i in range(n - o + 1, n + 1)})
            env = DvasEnvironment(profile=PROFILES[a.profile], n=n, t=t, behaviors=behaviors)
            counts = {"CORRECT": 0, "INCORRECT_SETTLED": 0, "NO_SETTLEMENT": 0}
            refuse_codes: set[str] = set()
            for i, sp in enumerate(specs):
                sp = unique(sp, f"qm:{n}:{t}:{m}:{o}:{goal}:{i}")
                invalid = goal == "approve_invalid"
                if invalid:
                    cap = sp.delivered_kwh - Decimal("0.5")
                    sp = replace(sp, cap_kwh=cap, requested_kwh=min(sp.requested_kwh, cap))
                r = env.run(sp)
                if invalid:
                    counts["CORRECT" if not r.ok else "INCORRECT_SETTLED"] += 1
                elif r.ok:
                    counts["CORRECT" if r.captured == honest_amount(sp) else "INCORRECT_SETTLED"] += 1
                    if r.ok and r.captured > sp.preauth_limit:
                        raise AssertionError("capture above hold accepted")
                else:
                    counts["NO_SETTLEMENT"] += 1
                if not r.ok:
                    refuse_codes.add(r.code.split("[")[0] if r.stage == "quorum" else r.code)
            exp = expected(t, n, m, o, goal)
            if exp == "CORRECT":
                holds = counts["CORRECT"] == len(specs)
            elif exp == "NO_SETTLEMENT":
                holds = counts["INCORRECT_SETTLED"] == 0
            elif exp == "PUBLIC_BOUND_REFUSES":
                holds = counts["INCORRECT_SETTLED"] == 0 and counts["CORRECT"] == 0
            else:  # SEMANTIC_BYPASS_POSSIBLE: documented trust boundary; record what happened
                holds = True
            rows.append({"config": f"{t}-of-{n}", "n": n, "t": t, "malicious_colluding": m, "offline": o,
                         "honest_available": n - m - o, "goal": goal, "malicious_behavior": beh if m else "",
                         "sessions": len(specs), **{k.lower(): v for k, v in counts.items()},
                         "refusal_codes": "|".join(sorted(refuse_codes)), "expected_regime": exp,
                         "within_trust_assumption": m < t, "matches_expectation": holds})
            print(rows[-1]["config"], f"m={m} o={o}", goal, counts, exp, "OK" if holds else "MISMATCH")
    write_csv(Path(a.out), rows)
    return 0 if all(r["matches_expectation"] for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
