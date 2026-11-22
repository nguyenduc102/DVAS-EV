"""PA-MSP / PAM-Proof ablation.

Variants (same SHA-256 binary Merkle commitment rho_t in every variant):

B0-full  disclose the whole committed layout. Verifier recomputes the root
         from all leaves (no sibling hashes).
B0-row   row-level disclosure: every field of each layout group that contains
         a required field, independent authentication paths.
B1       PA-MSP selected fields F_req, independent authentication paths.
B2       PA-MSP selected fields F_req, ordinary packed Merkle multiproof
         (shared siblings deduplicated), Merkle authenticity only.
B3       PA-MSP selected fields F_req, packed multiproof, predicate-
         completeness check + Merkle authenticity (= DVAS-EV PAM-Proof).

selection_gain = B0 - B1   (reported against B0-row and B0-full)
packing_gain   = B1 - B2
B3 vs B2: identical bytes by construction. B3 adds enforcement,
measured as the acceptance rate of authentic-but-incomplete openings.

Outputs: outputs/pam_ablation.csv (summary), outputs/raw/pam_ablation_raw.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, RAW, SCOPE, stats, write_csv, write_metadata  # noqa: E402

import time  # noqa: E402

from dbas_et.dvas.pam import ProofKind, commit, open_fields, verify_opening, leaf_hash, node_hash, root_from_merkle, pad_hash  # noqa: E402
from dbas_et.dvas.predicates import PREDICATES, required_fields  # noqa: E402
from dbas_et.dvas.protocol import DvasEnvironment  # noqa: E402
from dbas_et.dvas.profiles import PROFILES  # noqa: E402
from dbas_et.dvas.schema import LAYOUT_V1, REGISTRY  # noqa: E402
from dbas_et.dvas.canonical import encode_field  # noqa: E402
from dbas_et.dvas.workload import acn_sessions, mfev_sessions  # noqa: E402

REASONS = [r for r in PREDICATES]


def full_layout_verify(rho_t: str, values: dict) -> bool:
    n = len(LAYOUT_V1.field_names)
    base = 1
    while base < n:
        base <<= 1
    level = [leaf_hash(LAYOUT_V1, nm, values[nm]) for nm in LAYOUT_V1.field_names]
    level += [pad_hash(LAYOUT_V1, i) for i in range(n, base)]
    while len(level) > 1:
        level = [node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return root_from_merkle(LAYOUT_V1, level[0]) == rho_t


def row_fields(req: tuple[str, ...]) -> list[str]:
    groups = LAYOUT_V1.groups()
    touched = {REGISTRY.spec(n).group for n in req}
    return [n for g, names in groups.items() if g in touched for n in names]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--capsules", type=int, default=100)
    ap.add_argument("--repeats", type=int, default=15)
    ap.add_argument("--warmup", type=int, default=50)
    args = ap.parse_args()
    md = write_metadata("pam_ablation")

    env = DvasEnvironment(profile=PROFILES["C0"])
    specs = acn_sessions(max_rows=args.capsules // 2) + mfev_sessions(max_rows=args.capsules - args.capsules // 2)
    commitments = []
    for sp in specs:
        env.register_spec(sp)
        s = env.session(sp)
        commitments.append((sp.source, s.commit()))

    # warm-up
    for _ in range(args.warmup):
        c = commitments[0][1]
        verify_opening(c.rho_t, open_fields(c, required_fields(LAYOUT_V1, "settlement"), reason="settlement"),
                       reason="settlement")

    raw: list[dict] = []
    enforcement: dict[str, dict[str, int]] = {}
    for reason in REASONS:
        req = required_fields(LAYOUT_V1, reason)
        variants = {
            "B0-full": ("full", list(LAYOUT_V1.field_names), None, False),
            "B0-row": ("row", row_fields(req), ProofKind.INDEPENDENT, False),
            "B1": ("pamsp", list(req), ProofKind.INDEPENDENT, False),
            "B2": ("pamsp", list(req), ProofKind.MULTIPROOF, False),
            "B3": ("pamsp", list(req), ProofKind.MULTIPROOF, True),
        }
        for ci, (src, c) in enumerate(commitments):
            for vname, (sel, fields, kind, complete) in variants.items():
                if kind is None:
                    vals = c.values
                    opened_bytes = sum(len(encode_field(REGISTRY.spec(n), vals[n])) for n in fields)
                    siblings = 0
                    gen = lambda: {n: vals[n] for n in fields}  # noqa: E731
                    ver = lambda: full_layout_verify(c.rho_t, vals)  # noqa: E731
                else:
                    op = open_fields(c, fields, reason=reason, proof_kind=kind)
                    opened_bytes, siblings = op.opened_value_bytes(), op.sibling_hash_count
                    gen = lambda f=fields, k=kind: open_fields(c, f, reason=reason, proof_kind=k)  # noqa: E731
                    ver = lambda o=op, cc=complete: verify_opening(c.rho_t, o, reason=reason, check_completeness=cc)  # noqa: E731
                    assert ver().ok
                for rep in range(args.repeats):
                    t0 = time.perf_counter_ns(); gen(); g = time.perf_counter_ns() - t0
                    t0 = time.perf_counter_ns(); ok = ver(); v = time.perf_counter_ns() - t0
                    raw.append({"variant": vname, "reason": reason, "capsule": ci, "source": src, "rep": rep,
                                "disclosed_fields": len(fields), "opened_value_bytes": opened_bytes,
                                "sibling_hashes": siblings, "proof_bytes": siblings * 32,
                                "total_bytes": opened_bytes + siblings * 32, "gen_ns": g, "verify_ns": v,
                                "verified": bool(ok if isinstance(ok, bool) else ok.ok)})
        # enforcement experiment: every authentic opening that omits one required field
        acc = {"B2": 0, "B3": 0, "cases": 0}
        for _, c in commitments[:20]:
            for omit in req:
                sub = [n for n in req if n != omit]
                if not sub:
                    continue
                op = open_fields(c, sub, reason=reason, proof_kind=ProofKind.MULTIPROOF)
                acc["cases"] += 1
                acc["B2"] += verify_opening(c.rho_t, op, reason=reason, check_completeness=False).ok
                acc["B3"] += verify_opening(c.rho_t, op, reason=reason).ok
        enforcement[reason] = acc

    write_csv(RAW / "pam_ablation_raw.csv", raw)

    summary = []
    by: dict[tuple[str, str], list[dict]] = {}
    for r in raw:
        by.setdefault((r["reason"], r["variant"]), []).append(r)
    for (reason, v), rows in sorted(by.items()):
        g = stats([r["gen_ns"] / 1000 for r in rows])
        ve = stats([r["verify_ns"] / 1000 for r in rows])
        sz = stats([r["total_bytes"] for r in rows])
        enf = enforcement[reason]
        summary.append({
            "reason": reason, "variant": v, "n_samples": len(rows),
            "disclosed_fields": rows[0]["disclosed_fields"],
            "opened_value_bytes_median": stats([r["opened_value_bytes"] for r in rows])["median"],
            "sibling_hashes_median": stats([r["sibling_hashes"] for r in rows])["median"],
            "proof_bytes_median": stats([r["proof_bytes"] for r in rows])["median"],
            "total_bytes_median": sz["median"],
            "gen_us_median": round(g["median"], 3), "gen_us_p95": round(g["p95"], 3),
            "verify_us_median": round(ve["median"], 3), "verify_us_p95": round(ve["p95"], 3),
            "incomplete_openings_tested": enf["cases"] if v in ("B2", "B3") else "",
            "incomplete_openings_accepted": enf[v] if v in ("B2", "B3") else "",
            "scope": SCOPE,
        })
    # gains
    idx = {(r["reason"], r["variant"]): r for r in summary}
    gains = []
    for reason in REASONS:
        b0f, b0r, b1, b2, b3 = (idx[(reason, v)] for v in ("B0-full", "B0-row", "B1", "B2", "B3"))
        gains.append({
            "reason": reason, "variant": "GAINS",
            "selection_gain_fields_vs_row": b0r["disclosed_fields"] - b1["disclosed_fields"],
            "selection_gain_fields_vs_full": b0f["disclosed_fields"] - b1["disclosed_fields"],
            "selection_gain_bytes_vs_row": b0r["total_bytes_median"] - b1["total_bytes_median"],
            "selection_gain_bytes_vs_full": b0f["total_bytes_median"] - b1["total_bytes_median"],
            "packing_gain_bytes": b1["total_bytes_median"] - b2["total_bytes_median"],
            "packing_gain_sibling_hashes": b1["sibling_hashes_median"] - b2["sibling_hashes_median"],
            "b3_minus_b2_bytes": b3["total_bytes_median"] - b2["total_bytes_median"],
            "b3_minus_b2_verify_us": round(b3["verify_us_median"] - b2["verify_us_median"], 3),
            "b2_incomplete_accept_rate": round(b2["incomplete_openings_accepted"] / b2["incomplete_openings_tested"], 4)
            if b2["incomplete_openings_tested"] else "",
            "b3_incomplete_accept_rate": round(b3["incomplete_openings_accepted"] / b3["incomplete_openings_tested"], 4)
            if b3["incomplete_openings_tested"] else "",
        })
    write_csv(OUT / "pam_ablation.csv", summary + gains)

    # Decomposition: each effect is
    # attributed to exactly one mechanism.
    updated = []
    for reason in REASONS:
        b0f, b0r, b1, b2, b3 = (idx[(reason, v)] for v in ("B0-full", "B0-row", "B1", "B2", "B3"))
        for v, r in (("B0-full", b0f), ("B0-row", b0r), ("B1", b1), ("B2", b2), ("B3", b3)):
            updated.append({
                "reason": reason, "row_type": "variant", "variant": v,
                "semantic_disclosure_fields": r["disclosed_fields"],
                "disclosed_value_bytes": r["opened_value_bytes_median"],
                "auth_sibling_hashes": r["sibling_hashes_median"], "auth_proof_bytes": r["proof_bytes_median"],
                "total_bytes": r["total_bytes_median"],
                "incomplete_authentic_openings_tested": r["incomplete_openings_tested"],
                "incomplete_authentic_openings_accepted": r["incomplete_openings_accepted"],
                "gen_us_median": r["gen_us_median"], "gen_us_p95": r["gen_us_p95"],
                "verify_us_median": r["verify_us_median"], "verify_us_p95": r["verify_us_p95"],
            })
        b3_bytes_delta = b3["total_bytes_median"] - b2["total_bytes_median"]
        assert b3_bytes_delta == 0, "B2 and B3 must be byte-identical"
        effects = [
            ("selection_effect_vs_full (B0-full -> B1)", "PA-MSP field selection",
             b0f["disclosed_fields"] - b1["disclosed_fields"], b0f["total_bytes_median"] - b1["total_bytes_median"],
             "", b0f["verify_us_median"] - b1["verify_us_median"]),
            ("selection_effect_vs_row (B0-row -> B1)", "PA-MSP field selection",
             b0r["disclosed_fields"] - b1["disclosed_fields"], b0r["total_bytes_median"] - b1["total_bytes_median"],
             b0r["sibling_hashes_median"] - b1["sibling_hashes_median"], b0r["verify_us_median"] - b1["verify_us_median"]),
            ("packing_effect (B1 -> B2)", "standard packed Merkle multiproof",
             b1["disclosed_fields"] - b2["disclosed_fields"], b1["total_bytes_median"] - b2["total_bytes_median"],
             b1["sibling_hashes_median"] - b2["sibling_hashes_median"], b1["verify_us_median"] - b2["verify_us_median"]),
            ("completeness_effect (B2 -> B3)", "predicate-completeness verification policy",
             b2["disclosed_fields"] - b3["disclosed_fields"], b2["total_bytes_median"] - b3["total_bytes_median"],
             b2["sibling_hashes_median"] - b3["sibling_hashes_median"], b2["verify_us_median"] - b3["verify_us_median"]),
        ]
        for name, mech, dfields, dbytes, dsib, dver in effects:
            row = {"reason": reason, "row_type": "effect", "variant": name, "attributed_to": mech,
                   "fields_saved": dfields, "bytes_saved": dbytes, "sibling_hashes_saved": dsib,
                   "verify_us_saved": round(dver, 3)}
            if name.startswith("completeness"):
                row["incomplete_accepted_before"] = b2["incomplete_openings_accepted"]
                row["incomplete_accepted_after"] = b3["incomplete_openings_accepted"]
                row["incomplete_tested"] = b3["incomplete_openings_tested"]
                row["note"] = "no byte reduction is attributable to PAM completeness; its effect is rejection of authentic-but-incomplete openings"
            updated.append(row)
    write_csv(OUT / "pam_ablation_updated.csv", updated)
    print(f"wrote {OUT / 'pam_ablation.csv'} ({len(summary)} variant rows, {len(raw)} raw samples); cpu={md.get('cpu_model')}")
    for g in gains:
        if g["reason"] in ("settlement", "authorization", "delivery_cap"):
            print(g)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
