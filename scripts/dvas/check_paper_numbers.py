"""Collects the numbers reported in the paper -> <OUT>/paper_numbers.{json,csv}.

Every value is loaded from a generated output file and recorded with its
source file and derivation, so Abstract, tables, figures and body text can
all cite the same key.  The script also cross-checks internal consistency
(e.g. table totals equal raw counts) and exits non-zero on any mismatch.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, write_csv  # noqa: E402

N: dict[str, dict] = {}
ERRORS: list[str] = []


def rd(name):
    return list(csv.DictReader(open(OUT / name, encoding="utf-8")))


def put(key, value, source, derivation=""):
    N[key] = {"value": value, "source": source, "derivation": derivation}


def same(a, b, what):
    if str(a) != str(b):
        ERRORS.append(f"{what}: {a} != {b}")


def main() -> int:
    tests = rd("test_summary.csv") if (OUT / "test_summary.csv").exists() else []
    for r in tests:
        put(f"tests.{r['suite']}.passed", int(r["passed"]), "test_summary.csv")
        put(f"tests.{r['suite']}.failed", int(r["failed"]), "test_summary.csv")

    rr = rd("regression_rows.csv")
    for wl in ("acn_valid", "acn_original_cap", "acn_topup"):
        g = [r for r in rr if r["workload"] == wl]
        put(f"workload.{wl}.sessions", len(g), "regression_rows.csv", "count rows")
        put(f"workload.{wl}.settled", sum(r["dvas_ok"] == "True" for r in g), "regression_rows.csv", "dvas_ok")
        put(f"workload.{wl}.agree_with_legacy", sum(r["agree"] == "True" for r in g), "regression_rows.csv", "agree")
    put("workload.acn_original_cap.explained_legacy_over_hold_rows",
        [int(r["row_index"]) for r in rr if r.get("explained_legacy_over_hold") == "True"], "regression_rows.csv")
    mf = next(r for r in rd("regression_checks.csv") if r["check"].startswith("mfev_valid"))
    put("workload.mfev_valid.settled_of_sessions", mf["value"], "regression_checks.csv")
    mo = rd("multi_operator_results.csv")
    put("workload.multi_operator.sessions", len(mo), "multi_operator_results.csv")
    put("workload.multi_operator.settled", sum(r["ok"] == "True" for r in mo), "multi_operator_results.csv")
    put("workload.multi_operator.cross_domain", sum(r["cross_domain"] == "True" for r in mo), "multi_operator_results.csv")
    put("workload.multi_operator.home_cpo_pairs", len({(r["home_operator"], r["cpo"]) for r in mo}), "multi_operator_results.csv")

    att = rd("attack_results.csv")
    put("attacks.cases", len(att), "attack_results.csv")
    put("attacks.attack_types", len({r["attack"] for r in att}), "attack_results.csv")
    for g in ("systematic", "randomized"):
        put(f"attacks.{g}", sum(r["generation"] == g for r in att), "attack_results.csv")
    put("attacks.compound", sum(r["compound"] == "True" for r in att), "attack_results.csv")
    for f in ("A", "B", "C"):
        put(f"attacks.family_{f}", sum(r["family"] == f for r in att), "attack_results.csv")
    put("attacks.unexpected_accepts", sum(r["actual"] == "ACCEPTED" for r in att), "attack_results.csv")
    put("attacks.harness_errors", sum(r["actual"] == "ERROR" for r in att), "attack_results.csv")
    tb = {r["family"]: r for r in rd("tables/table_B_adversarial.csv")}
    same(tb["TOTAL"]["cases"], len(att), "table B total vs raw attack count")
    same(tb["TOTAL"]["unexpected_accepts"], N["attacks.unexpected_accepts"]["value"], "table B unexpected accepts")

    rv = rd("legacy_regression.csv")
    put("legacy_regression.passed", f"{sum(r['pass'] == 'True' for r in rv)}/{len(rv)}", "legacy_regression.csv")

    fp = rd("formal_properties_results.csv")
    for prop in sorted({r["property"] for r in fp}):
        rows = [r for r in fp if r["property"] == prop]
        put(f"formal.{prop}.trials", sum(int(r["trials"]) for r in rows), "formal_properties_results.csv")
        put(f"formal.{prop}.passed", sum(int(r["passed"]) for r in rows), "formal_properties_results.csv")
    put("formal.contexts", int(fp[0]["contexts"]), "formal_properties_results.csv")
    for r in rd("minimality_classification.csv"):
        put(f"minimality.{r['predicate']}", r["classification"], "minimality_classification.csv")

    pu = rd("pam_ablation_updated.csv")
    for r in pu:
        if r["reason"] != "settlement":
            continue
        if r["row_type"] == "variant":
            v = r["variant"]
            for k in ("semantic_disclosure_fields", "auth_sibling_hashes", "auth_proof_bytes", "total_bytes",
                      "gen_us_median", "verify_us_median", "verify_us_p95"):
                put(f"pam.settlement.{v}.{k}", r[k], "pam_ablation_updated.csv")
            if r["incomplete_authentic_openings_tested"]:
                put(f"pam.settlement.{v}.incomplete_accepted",
                    f"{r['incomplete_authentic_openings_accepted']}/{r['incomplete_authentic_openings_tested']}",
                    "pam_ablation_updated.csv")
        else:
            key = r["variant"].split(" ")[0]
            for k in ("fields_saved", "sibling_hashes_saved", "bytes_saved", "verify_us_saved"):
                put(f"pam.settlement.{key}.{k}", r[k], "pam_ablation_updated.csv")
    same(N["pam.settlement.completeness_effect.bytes_saved"]["value"], "0.0", "completeness effect bytes")
    put("pam.capsules", sum(1 for r in csv.DictReader(open(OUT / "raw" / "pam_ablation_raw.csv"))
                            if r["variant"] == "B3" and r["reason"] == "settlement" and r["rep"] == "0"),
        "raw/pam_ablation_raw.csv", "distinct capsules (rep 0)")

    for r in rd("tables/table_D_quorum_tradeoff.csv"):
        c = r["configuration"].replace(" ", "_")
        for k in ("per_verifier_ms_median", "critical_path_ms_median", "critical_path_ms_p95", "rbc_bytes_median",
                  "signatures", "gas_release", "observed_tolerance"):
            put(f"quorum.{c}.{k}", r[k], "tables/table_D_quorum_tradeoff.csv (from quorum_cost.csv, solidity_gas.csv, quorum_fault_matrix.csv)")
    fm = rd("quorum_fault_matrix.csv")
    put("quorum.fault_matrix.cells", len(fm), "quorum_fault_matrix.csv")
    put("quorum.fault_matrix.sessions_per_cell", int(fm[0]["sessions"]), "quorum_fault_matrix.csv")
    put("quorum.fault_matrix.matching", sum(r["matches_expectation"] == "True" for r in fm), "quorum_fault_matrix.csv")
    sb = rd("security_boundary.csv")
    put("security.capture_above_hold_accepted_total", sum(int(r["capture_above_hold_accepted"]) for r in sb), "security_boundary.csv")
    put("security.replay_accepted_total", sum(int(r["replay_accepted"]) for r in sb if r["replay_accepted"] != ""), "security_boundary.csv")
    put("security.f_lt_t_incorrect_settlements",
        sum(int(r["semantic_incorrect_settlement_observed"]) for r in sb if r["within_f_lt_t_assumption"] == "True"),
        "security_boundary.csv")

    for r in rd("pq_ablation.csv"):
        if r["config"] != "2-of-3":
            continue
        p = r["profile"]
        for k in ("total_ms_median", "total_ms_p95", "authorization_ms_median", "private_envelope_bytes_median",
                  "rbc_bytes_median", "auth_sig_bytes", "verifier_sig_bytes", "kem_ct_bytes"):
            put(f"pq.{p}.2of3.{k}", r[k], "pq_ablation.csv")
        put(f"pq.{p}.pq_status", r["pq_status"], "pq_ablation.csv")
    for r in rd("solidity_gas.csv"):
        put(f"gas.{r['contract_suite']}.{r['measurement']}", int(r["gas"]), "solidity_gas.csv", r.get("note", ""))
    for r in rd("baselines.csv"):
        put(f"baseline.{r['baseline']}.total_ms_median", r["total_ms_median"], "baselines.csv")
        put(f"baseline.{r['baseline']}.public_bytes_median", r["public_bytes_median"], "baselines.csv")
    for r in rd("baseline_attack_detection.csv"):
        put(f"baseline.{r['baseline']}.{r['attack']}.detected", f"{r['detected']}/{r['cases']}", "baseline_attack_detection.csv")
    sd = json.loads((OUT / "standards_demo_result.json").read_text())
    put("standards_demo.settled_ok", sd["settled_ok"], "standards_demo_result.json")
    put("standards_demo.captured", sd["captured"], "standards_demo_result.json")

    (OUT / "paper_numbers.json").write_text(json.dumps(N, indent=2, sort_keys=True, default=str))
    write_csv(OUT / "paper_numbers.csv", [{"key": k, **v} for k, v in sorted(N.items())])
    (OUT / "paper_numbers_consistency.txt").write_text("\n".join(ERRORS) or "OK: no inconsistencies")
    print(f"{len(N)} numbers; inconsistencies: {len(ERRORS)}")
    for e in ERRORS:
        print("INCONSISTENT", e)
    return 0 if not ERRORS else 1


if __name__ == "__main__":
    raise SystemExit(main())
