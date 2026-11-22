"""Compare the larger paper-artifact campaign (<OUT>) with the previously validated
outputs (outputs/) and flag material deviations -> <OUT>/scale_comparison.{csv,md}.

Rules (flags are reported, not hidden):
  invariants  (unexpected accepts, property violations, minimality classes,
               fault-matrix mismatches, completeness bytes): must be identical / zero
  sizes       (bytes, sibling hashes, field counts): deviation > 2 % flagged
  timings     (median latencies): deviation > 25 % flagged (machine noise expected,
               timings are local protocol-processing measurements)
  gas         must be identical (deterministic EVM execution)
More test cases do not make a formal proof.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, ROOT, write_csv  # noqa: E402

BASE = ROOT / "results" / "paper_artifact"
R: list[dict] = []


def rd(d, n):
    p = d / n
    return list(csv.DictReader(open(p, encoding="utf-8"))) if p.exists() else []


def add(kind, metric, base, new, flag, note=""):
    R.append({"kind": kind, "metric": metric, "validated": base, "paper_artifact": new,
              "deviation_pct": "" if base in ("", None) or new in ("", None) or kind in ("invariant", "gas") or float(base) == 0
              else round(100 * (float(new) - float(base)) / float(base), 2), "flagged": flag, "note": note})


def rel(a, b):
    return abs(float(b) - float(a)) / abs(float(a)) if float(a) else 0.0


def main() -> int:
    if OUT.resolve() == BASE.resolve():
        print("DVAS_OUT must point to the new campaign directory")
        return 2
    a0, a1 = rd(BASE, "attack_results.csv"), rd(OUT, "attack_results.csv")
    for k in ("ACCEPTED", "ERROR"):
        n0, n1 = sum(r["actual"] == k for r in a0), sum(r["actual"] == k for r in a1)
        add("invariant", f"attacks {k.lower()}", n0, n1, n1 != 0, f"cases {len(a0)} -> {len(a1)}")
    f0, f1 = rd(BASE, "formal_properties_results.csv"), rd(OUT, "formal_properties_results.csv")
    for prop in sorted({r["property"] for r in f1}):
        v0 = sum(int(r["failed"]) for r in f0 if r["property"] == prop)
        v1 = sum(int(r["failed"]) for r in f1 if r["property"] == prop)
        t1 = sum(int(r["trials"]) for r in f1 if r["property"] == prop)
        t0 = sum(int(r["trials"]) for r in f0 if r["property"] == prop)
        add("invariant", f"formal {prop} failures", v0, v1, v1 != 0, f"trials {t0} -> {t1}")
    m1 = {r["predicate"]: r["classification"] for r in rd(OUT, "minimality_classification.csv")}
    exp = {p: "BOOLEAN_MINIMAL" for p in m1}
    exp.update({"authorization": "NOT_MINIMAL", "pricing": "DECISION_MINIMAL_ONLY"})
    add("invariant", "minimality classifications", "expected set", "same" if m1 == exp else str(m1), m1 != exp)
    q0, q1 = rd(BASE, "quorum_fault_matrix.csv"), rd(OUT, "quorum_fault_matrix.csv")
    add("invariant", "fault-matrix cells not matching expectation",
        sum(r["matches_expectation"] != "True" for r in q0), sum(r["matches_expectation"] != "True" for r in q1),
        any(r["matches_expectation"] != "True" for r in q1), f"sessions/cell {q0[0]['sessions'] if q0 else '-'} -> {q1[0]['sessions']}")
    p0 = {(r["reason"], r["variant"]): r for r in rd(BASE, "pam_ablation_updated.csv") if r["row_type"] == "variant"}
    p1 = {(r["reason"], r["variant"]): r for r in rd(OUT, "pam_ablation_updated.csv") if r["row_type"] == "variant"}
    for key in sorted(p1):
        if key not in p0:
            continue
        for m in ("total_bytes", "auth_sibling_hashes", "semantic_disclosure_fields"):
            add("size", f"PAM {key[0]} {key[1]} {m}", p0[key][m], p1[key][m], rel(p0[key][m], p1[key][m]) > 0.02)
        add("timing", f"PAM {key[0]} {key[1]} verify_us_median", p0[key]["verify_us_median"], p1[key]["verify_us_median"],
            rel(p0[key]["verify_us_median"], p1[key]["verify_us_median"]) > 0.25)
    c0 = {r["config"]: r for r in rd(BASE, "quorum_cost.csv")}
    for r in rd(OUT, "quorum_cost.csv"):
        b = c0.get(r["config"])
        if b:
            for m in ("per_verifier_ms_median", "critical_path_ms_median"):
                add("timing", f"quorum {r['config']} {m}", b[m], r[m], rel(b[m], r[m]) > 0.25)
            add("size", f"quorum {r['config']} rbc_bytes_median", b["rbc_bytes_median"], r["rbc_bytes_median"],
                rel(b["rbc_bytes_median"], r["rbc_bytes_median"]) > 0.02)
    pq0 = {(r["profile"], r["config"]): r for r in rd(BASE, "pq_ablation.csv")}
    for r in rd(OUT, "pq_ablation.csv"):
        b = pq0.get((r["profile"], r["config"]))
        if b:
            add("timing", f"PQ {r['profile']} {r['config']} total_ms_median", b["total_ms_median"], r["total_ms_median"],
                rel(b["total_ms_median"], r["total_ms_median"]) > 0.25)
            add("size", f"PQ {r['profile']} {r['config']} private_envelope_bytes", b["private_envelope_bytes_median"],
                r["private_envelope_bytes_median"], rel(b["private_envelope_bytes_median"], r["private_envelope_bytes_median"]) > 0.02)
    g0 = {(r.get("contract_suite"), r["measurement"]): r["gas"] for r in rd(BASE, "solidity_gas.csv")}
    for r in rd(OUT, "solidity_gas.csv"):
        b = g0.get((r["contract_suite"], r["measurement"]))
        if b is not None:
            add("gas", f"{r['contract_suite']}.{r['measurement']}", b, r["gas"], b != r["gas"])
    write_csv(OUT / "scale_comparison.csv", R)
    flagged = [r for r in R if r["flagged"]]
    flag_rows = [f"| {r['kind']} | {r['metric']} | {r['validated']} | {r['paper_artifact']} | {r['deviation_pct']} | {r['note']} |"
                 for r in flagged]
    lines = ["# Larger campaign vs validated outputs", "",
             "More test cases strengthen the evidence but are not a formal proof.", "",
             f"Compared metrics: {len(R)}; flagged: {len(flagged)} "
             f"(invariant flags: {sum(r['kind'] == 'invariant' for r in flagged)}).", "",
             "| kind | metric | validated | paper artifact | deviation % | note |", "|---|---|---|---|---|---|",
             *(flag_rows or ["| - | no flagged deviations | | | | |"]), ""]
    (OUT / "scale_comparison.md").write_text("\n".join(lines))
    print(f"compared {len(R)} metrics, flagged {len(flagged)}")
    for r in flagged:
        print("FLAG", r)
    return 1 if any(r["kind"] == "invariant" and r["flagged"] for r in R) else 0


if __name__ == "__main__":
    raise SystemExit(main())
