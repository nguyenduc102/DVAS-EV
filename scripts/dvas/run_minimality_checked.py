"""Checked minimality analysis -> outputs/minimality_checked.csv + outputs/minimality_checked_summary.md.

Analysis only: the production selector stays dependency-selected (sufficiency).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, write_csv, write_metadata  # noqa: E402

from dbas_et.dvas.formal_checks import build_contexts  # noqa: E402
from dbas_et.dvas.minimality import VACUITY_LEMMAS, classify  # noqa: E402
from dbas_et.dvas.predicates import PREDICATES  # noqa: E402
from dbas_et.dvas.workload import acn_sessions, mfev_sessions  # noqa: E402

DOMAIN = ("STRING: non-empty NFC strings; ENUM: registered values only; FIXED6: >= 0; TIMESTAMP: integers. "
          "Evidence: real session evidence plus tightened variants that make bound atoms active.")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--acn", type=int, default=5)
    ap.add_argument("--mfev", type=int, default=3)
    a = ap.parse_args()
    write_metadata("minimality_checked")
    ctx = [c for _, _, c in build_contexts(acn_sessions(max_rows=a.acn) + mfev_sessions(max_rows=a.mfev))]
    rows, summ = [], []
    for reason in PREDICATES:
        pc = classify(reason, ctx)
        rows += pc.rows
        summ.append((reason, len(pc.f_r), pc.classification,
                     sum(r["boolean_witness"] for r in pc.rows), sum(r["decision_witness"] for r in pc.rows),
                     ", ".join(f"{r['field']}: {r['boolean_nonnecessity_certificate'] or r['decision_nonnecessity_certificate']}"
                               for r in pc.rows if r["boolean_nonnecessity_certificate"] or r["decision_nonnecessity_certificate"])))
        print(reason, pc.classification)
    for r in rows:
        r["domain"] = DOMAIN
        r["contexts"] = len(ctx)
    write_csv(OUT / "minimality_checked.csv", rows)
    write_csv(OUT / "minimality_classification.csv",
              [{"predicate": r, "F_r_size": n, "classification": c, "boolean_witnesses": b, "decision_witnesses": d,
                "nonnecessity_certificates": cert} for r, n, c, b, d, cert in summ])
    md = ["# Checked minimality analysis", "",
          "Analysis tool `dbas_et/dvas/minimality.py`; runner `scripts/dvas/run_minimality_checked.py`. "
          "The runtime selector is unchanged and claims **sufficiency only**.", "",
          f"Valid semantic domain: {DOMAIN}", "",
          f"Contexts: {len(ctx)} real sessions ({a.acn} ACN + {a.mfev} MFEV).", "",
          "A witness (c1, c2, e), with c1 and c2 differing only in f and a different outcome, is a constructive "
          "proof that f is necessary. A non-necessity certificate is a proof that f is NOT necessary. A missing "
          "witness alone proves nothing (UNRESOLVED).", "",
          "| predicate | \\|F_r\\| | classification | Boolean witnesses | decision witnesses | non-necessity certificates |",
          "|---|---|---|---|---|---|",
          *[f"| {r} | {n} | **{c}** | {b}/{n} | {d}/{n} | {cert or '-'} |" for r, n, c, b, d, cert in summ], "",
          "Lemmas used:", *[f"- `{k}`: {v}" for k, v in VACUITY_LEMMAS.items()],
          "- `SINGLETON_DOMAIN`: a field whose valid domain has one value cannot distinguish two valid assignments.", "",
          "Classification rules: BOOLEAN_MINIMAL = every operand has a Boolean witness; DECISION_MINIMAL_ONLY = every "
          "operand has a decision witness (truth value or derived amount) and every operand without a Boolean "
          "witness carries a Boolean non-necessity certificate; NOT_MINIMAL = some operand has a decision "
          "non-necessity certificate; otherwise UNRESOLVED.", "",
          "These results are properties of the specific predicates under the stated domain. They are not a "
          "general minimality claim for the selector, and protocol semantics were not changed to make them minimal.", ""]
    (OUT / "minimality_checked_summary.md").write_text("\n".join(md))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
