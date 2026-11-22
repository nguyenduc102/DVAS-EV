"""Summary tables, derived only from raw/summary experiment CSVs in <OUT>.

Writes <OUT>/tables/table_{A..F}_*.csv and <OUT>/tables/paper_tables.md.
No number in this script is typed by hand.
"""

from __future__ import annotations

import csv
import statistics
import sys
from collections import Counter, defaultdict
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, write_csv  # noqa: E402

T = OUT / "tables"
PAM_REASONS = ("settlement", "authorization", "delivery_cap", "dispute:over_cap")


def rd(name: str) -> list[dict]:
    return list(csv.DictReader(open(OUT / name, encoding="utf-8")))


def table_a() -> list[dict]:
    rows = rd("regression_rows.csv")
    out = []
    for wl in ("acn_valid", "acn_original_cap", "acn_topup"):
        g = [r for r in rows if r["workload"] == wl]
        settled = [r for r in g if r["dvas_ok"] == "True"]
        errs = [abs(Decimal(r["dvas_captured"]) - Decimal(r["expected_amount"])) for r in settled]
        exact = [abs(Decimal(r["dvas_captured"]) - Decimal(r["exact_tariff_amount"])) for r in settled]
        out.append({"workload": wl, "source": "ACN-Data", "sessions": len(g), "settled": len(settled),
                    "refused": len(g) - len(settled),
                    "agree_with_legacy": sum(r["agree"] == "True" for r in g),
                    "explained_legacy_over_hold": sum(r.get("explained_legacy_over_hold") == "True" for r in g),
                    "max_abs_error_vs_exact_tariff": str(max(exact)) if exact else "",
                    "max_abs_error_vs_dataset_column": str(max(errs)) if errs else "",
                    "rows_where_dataset_column_differs": sum(e != 0 for e in errs)})
    chk = rd("regression_checks.csv")
    mf = next(r for r in chk if r["check"].startswith("mfev_valid"))
    n_ok, n = mf["value"].split("/")
    out.append({"workload": "mfev_valid", "source": "MFEV", "sessions": int(n), "settled": int(n_ok),
                "refused": int(n) - int(n_ok), "agree_with_legacy": "n/a (no legacy MFEV path)",
                "explained_legacy_over_hold": "", "max_abs_error_vs_exact_tariff": "",
                "max_abs_error_vs_dataset_column": mf["note"].split("=")[-1], "rows_where_dataset_column_differs": ""})
    mo = rd("multi_operator_results.csv")
    out.append({"workload": "multi_operator (ACN+MFEV, 3 eMSP x 3 CPO)", "source": "ACN-Data + MFEV",
                "sessions": len(mo), "settled": sum(r["ok"] == "True" for r in mo),
                "refused": sum(r["ok"] != "True" for r in mo),
                "agree_with_legacy": f"cross-domain {sum(r['cross_domain'] == 'True' for r in mo)}",
                "explained_legacy_over_hold": "",
                "max_abs_error_vs_exact_tariff": "0" if all(r["amount_exact"] == "True" for r in mo if r["ok"] == "True") else "nonzero",
                "max_abs_error_vs_dataset_column": "", "rows_where_dataset_column_differs": ""})
    return out


def table_b() -> list[dict]:
    att = rd("attack_results.csv")
    out = []
    groups = defaultdict(list)
    for r in att:
        groups[(r["family"], r["generation"], r["compound"])].append(r)
    names = {"A": "single-field", "B": "compound", "C": "sequence/state"}
    for (f, g, c), rs in sorted(groups.items()):
        out.append({"family": f"{f} ({names[f]})", "generation": g, "compound": c, "attack_types": len({r["attack"] for r in rs}),
                    "cases": len(rs), "expected_rejections": sum(r["expected"] == "REJECT" for r in rs),
                    "rejected": sum(r["actual"] == "REJECTED" for r in rs),
                    "unexpected_accepts": sum(r["actual"] == "ACCEPTED" for r in rs),
                    "harness_errors": sum(r["actual"] == "ERROR" for r in rs)})
    out.append({"family": "TOTAL", "generation": "all", "compound": "", "attack_types": len({r["attack"] for r in att}),
                "cases": len(att), "expected_rejections": sum(r["expected"] == "REJECT" for r in att),
                "rejected": sum(r["actual"] == "REJECTED" for r in att),
                "unexpected_accepts": sum(r["actual"] == "ACCEPTED" for r in att),
                "harness_errors": sum(r["actual"] == "ERROR" for r in att)})
    rr = rd("legacy_regression.csv")
    out.append({"family": "legacy regression R1-R5", "generation": "fixed", "compound": "", "attack_types": len(rr),
                "cases": len(rr), "expected_rejections": len(rr), "rejected": sum(r["pass"] == "True" for r in rr),
                "unexpected_accepts": sum(r["pass"] != "True" for r in rr), "harness_errors": 0})
    return out


def table_c() -> tuple[list[dict], list[dict]]:
    pu = rd("pam_ablation_updated.csv")
    var = [{"reason": r["reason"], "variant": r["variant"], "fields": r["semantic_disclosure_fields"],
            "sibling_hashes": r["auth_sibling_hashes"], "proof_bytes": r["auth_proof_bytes"],
            "disclosed_value_bytes": r["disclosed_value_bytes"], "total_bytes": r["total_bytes"],
            "gen_us_median": r["gen_us_median"], "verify_us_median": r["verify_us_median"],
            "verify_us_p95": r["verify_us_p95"],
            "incomplete_authentic_accepted": (f"{r['incomplete_authentic_openings_accepted']}/{r['incomplete_authentic_openings_tested']}"
                                              if r["incomplete_authentic_openings_tested"] else "")}
           for r in pu if r["row_type"] == "variant" and r["reason"] in PAM_REASONS]
    eff = [{"reason": r["reason"], "effect": r["variant"], "attributed_to": r["attributed_to"],
            "fields_saved": r["fields_saved"], "sibling_hashes_saved": r["sibling_hashes_saved"],
            "bytes_saved": r["bytes_saved"], "verify_us_saved": r["verify_us_saved"],
            "incomplete_accepted_before_after": (f"{r['incomplete_accepted_before']} -> {r['incomplete_accepted_after']} of {r['incomplete_tested']}"
                                                 if r.get("incomplete_tested") else "")}
           for r in pu if r["row_type"] == "effect" and r["reason"] in PAM_REASONS]
    for e in eff:
        if e["effect"].startswith("completeness"):
            assert float(e["bytes_saved"]) == 0, "no byte reduction may be attributed to B2->B3"
    return var, eff


def gas_for(config: str) -> str:
    """Gas of the settlement call for a quorum_cost.csv configuration, from solidity_gas.csv."""
    gas = {(r["contract_suite"], r["measurement"]): r["gas"] for r in rd("solidity_gas.csv")}
    if config.startswith("legacy"):
        return gas.get(("DBASETGasFeasibilityMeasured", "releaseByRBC"), "")
    t, n = config.replace("DVAS-EV ", "").split("-of-")
    return gas.get(("DVASQuorumSettle", f"releaseByQuorumRBC_{t}of{n}"), "")


def table_d() -> list[dict]:
    qc = rd("quorum_cost.csv")
    fm = rd("quorum_fault_matrix.csv")
    out = []
    for r in qc:
        cfg = r["config"].replace("DVAS-EV ", "")
        if r["config"].startswith("DVAS"):
            cells = [x for x in fm if x["config"] == cfg]
            max_mal = max((int(x["malicious_colluding"]) for x in cells if x["goal"] == "inflate_valid"
                           and x["incorrect_settled"] == "0" and x["offline"] == "0"), default=0)
            max_off = max((int(x["offline"]) for x in cells if x["goal"] == "inflate_valid"
                           and x["malicious_colluding"] == "0" and int(x["correct"]) == int(x["sessions"])), default=0)
            tol = (f"up to {max_mal} malicious OR up to {max_off} offline (faults count together)" if cells
                   else ("none (t=1)" if cfg == "1-of-1" else ""))
        else:
            tol = "none (single verifier)"
        out.append({"configuration": r["config"], "per_verifier_ms_median": r["per_verifier_ms_median"],
                    "critical_path_ms_median": r["critical_path_ms_median"], "critical_path_ms_p95": r["critical_path_ms_p95"],
                    "total_verifier_cpu_ms_median": r["total_verifier_cpu_ms_median"],
                    "rbc_bytes_median": r["rbc_bytes_median"], "rbc_encoding": r["rbc_size_note"],
                    "signatures": r["signatures_in_rbc"], "gas_release": gas_for(r["config"]),
                    "observed_tolerance": tol, "settles_with_1_offline": r["settles_with_1_offline"],
                    "safe_with_1_malicious": r["safe_with_1_malicious"]})
    return out


def table_e() -> list[dict]:
    pq = rd("pq_ablation.csv")
    names = {"C0": "classical", "C1": "ML-DSA authorization only", "C2": "ML-KEM private evidence only",
             "C3": "hybrid (ML-DSA+ECDSA auth, ML-KEM, ECDSA meter/RBC)", "C4": "hybrid + ML-DSA attestations (off-chain only)"}
    return [{"profile": r["profile"], "description": names[r["profile"]], "pq_status": r["pq_status"], "config": r["config"],
             "authorization_ms": r["authorization_ms_median"], "receipt_generation_ms": r["receipt_generation_ms_median"],
             "private_protection_ms": r["private_protection_ms_median"], "private_opening_ms": r["private_opening_ms_median"],
             "verifier_ms": r["verifier_processing_ms_median"], "rbc_quorum_ms": r["rbc_quorum_ms_median"],
             "total_ms_median": r["total_ms_median"], "total_ms_p95": r["total_ms_p95"],
             "auth_sig_bytes": r["auth_sig_bytes"], "verifier_sig_bytes": r["verifier_sig_bytes"],
             "kem_ct_bytes": r["kem_ct_bytes"], "private_envelope_bytes": r["private_envelope_bytes_median"],
             "rbc_bytes": r["rbc_bytes_median"]} for r in pq]


def table_f() -> list[dict]:
    fr = rd("formal_properties_results.csv")
    agg = defaultdict(lambda: [0, 0, 0])
    for r in fr:
        a = agg[r["property"]]
        a[0] += int(r["trials"]); a[1] += int(r["passed"]); a[2] = int(r.get("contexts") or 0)
    out = [{"item": k, "trials": v[0], "passed": v[1], "contexts": v[2], "holds": v[0] == v[1]} for k, v in sorted(agg.items())]
    return out


def table_g() -> list[dict]:
    return rd("minimality_classification.csv")


def table_h() -> list[dict]:
    return [{k: r[k] for k in ("config", "malicious_colluding", "offline", "available", "sessions_per_goal",
                               "semantic_incorrect_settlement_possible", "settlement_possible",
                               "capture_above_hold_possible", "replay_possible", "expected_reason")}
            for r in rd("security_boundary.csv")]


def table_i() -> list[dict]:
    return rd("legacy_regression.csv")


def md(title: str, rows: list[dict]) -> list[str]:
    if not rows:
        return []
    keys = list(rows[0])
    return [f"### {title}", "", "| " + " | ".join(keys) + " |", "|" + "---|" * len(keys),
            *["| " + " | ".join(str(r.get(k, "")) for k in keys) + " |" for r in rows], ""]


def main() -> int:
    T.mkdir(parents=True, exist_ok=True)
    a, b = table_a(), table_b()
    cv, ce = table_c()
    d, e, f = table_d(), table_e(), table_f()
    g, h, i = table_g(), table_h(), table_i()
    for name, rows in [("table_A_workloads", a), ("table_B_adversarial", b), ("table_C_pam_variants", cv),
                       ("table_C_pam_effects", ce), ("table_D_quorum_tradeoff", d), ("table_E_pq_profiles", e),
                       ("table_F_formal_properties", f), ("table_G_minimality", g), ("table_H_security_boundary", h),
                       ("table_I_legacy_regression", i)]:
        write_csv(T / f"{name}.csv", rows)
    lines = ["# Paper tables (generated)", "",
             "Generated by `scripts/dvas/make_paper_artifact_tables.py` from the CSV files in this directory's parent. "
             "Timings are local protocol-processing latency; gas is the gasleft() delta in Foundry tests.", ""]
    for title, rows in [("A. Correctness / workloads", a), ("B. Adversarial validation", b),
                        ("C1. PAM decomposition: variants", cv), ("C2. PAM decomposition: effects (completeness effect has 0 bytes by construction)", ce),
                        ("D. Quorum trade-off", d), ("E. PQ/hybrid profiles", e), ("F. Formal-property checks", f),
                        ("G. Checked minimality (analysis only; selector claims sufficiency)", g),
                        ("H. Security / trust boundary", h), ("I. Legacy regression (legacy vs DVAS-EV)", i)]:
        lines += md(title, rows)
    (T / "paper_tables.md").write_text("\n".join(lines))
    print("wrote", T)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
