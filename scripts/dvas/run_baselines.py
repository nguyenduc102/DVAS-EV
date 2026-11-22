"""Controlled architectural baselines.

Outputs
  outputs/baselines.csv                  per-baseline summary (median per phase, op counts, bytes)
  outputs/baseline_attack_detection.csv  same three hold-bounded attacks against every baseline
  outputs/raw/baselines_raw.csv          per-session, per-phase raw rows
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, RAW, SCOPE, stats, write_csv, write_metadata  # noqa: E402

from dbas_et.dvas.attacks import unique  # noqa: E402
from dbas_et.dvas.baselines import ATTACKS, BASELINES, PHASES, detects, eligible  # noqa: E402
from dbas_et.dvas.workload import acn_sessions, honest_amount  # noqa: E402

FEATURES = {
    "FullEscrow": dict(pre_service_commitment="full_public_record", selective_disclosure=False,
                       predicate_completeness="n/a (everything public)", private_evidence=False,
                       meter_bound_private_evidence=False, verifier_quorum=False, on_chain_semantics=True),
    "HashAnchor": dict(pre_service_commitment="hash_only", selective_disclosure=False,
                       predicate_completeness=False, private_evidence="operator-held", meter_bound_private_evidence=False,
                       verifier_quorum=False, on_chain_semantics=False),
    "CDR": dict(pre_service_commitment=False, selective_disclosure=False, predicate_completeness=False,
                private_evidence="operator-held", meter_bound_private_evidence=False, verifier_quorum=False,
                on_chain_semantics=False),
    "DVAS-EV": dict(pre_service_commitment="merkle_root", selective_disclosure=True, predicate_completeness=True,
                    private_evidence="ML-KEM+AEAD (C3)", meter_bound_private_evidence=True, verifier_quorum="2-of-3",
                    on_chain_semantics="public invariants only"),
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=200)
    ap.add_argument("--warmup", type=int, default=20)
    ap.add_argument("--attack-rows", type=int, default=30)
    args = ap.parse_args()
    write_metadata("baselines")
    specs = [s for s in acn_sessions(max_rows=4 * (args.sessions + args.warmup)) if eligible(s)]
    specs = specs[: args.sessions + args.warmup]
    raw, summary, detection = [], [], []
    for name, cls in BASELINES.items():
        b = cls()
        for i, sp in enumerate(specs):
            run = b.run(unique(sp, f"honest:{name}:{i}"))
            if i < args.warmup:
                continue
            assert run.ok and run.captured == honest_amount(sp), (name, run.ok, run.captured, honest_amount(sp))
            row = {"baseline": name, "session": i, "ok": run.ok, "public_bytes": run.public_bytes,
                   "private_bytes": run.private_bytes, "retained_objects": run.retained_objects}
            for ph in PHASES:
                row[f"{ph}_ms"] = run.phases[ph].ms
                for k, v in run.phases[ph].ops.items():
                    row[f"{ph}.{k}"] = v
            row["total_ms"] = sum(run.phases[ph].ms for ph in PHASES)
            raw.append(row)
        rows = [r for r in raw if r["baseline"] == name]
        agg = {"baseline": name, "sessions": len(rows), "scope": SCOPE + "; controlled architectural baseline"}
        for ph in PHASES + ("total",):
            st = stats([r[f"{ph}_ms"] for r in rows])
            agg[f"{ph}_ms_median"], agg[f"{ph}_ms_p95"] = round(st["median"], 4), round(st["p95"], 4)
        opk = defaultdict(list)
        for r in rows:
            tot = defaultdict(int)
            for k, v in r.items():
                if "." in k:
                    tot[k.split(".", 1)[1]] += v
            for k in ("hash", "sig_gen", "sig_verify", "kem_encap", "kem_decap", "aead_enc", "aead_dec",
                      "proof_gen", "proof_verify", "state_transition", "bound_check", "retained_object",
                      "registry_lookup"):
                opk[k].append(tot.get(k, 0))
        for k, v in opk.items():
            agg[f"ops_{k}_median"] = stats(v)["median"]
        for k in ("public_bytes", "private_bytes", "retained_objects"):
            agg[f"{k}_median"] = stats([r[k] for r in rows])["median"]
        agg.update({f"feature_{k}": v for k, v in FEATURES[name].items()})
        summary.append(agg)
        for atk in ATTACKS:
            det = [detects(cls(), sp, atk) for sp in specs[: args.attack_rows]]
            detection.append({"baseline": name, "attack": atk, "cases": len(det),
                              "detected": sum(d for d, _ in det), "outcomes": "|".join(sorted({o.split(':')[0] for _, o in det}))})
    write_csv(RAW / "baselines_raw.csv", raw)
    write_csv(OUT / "baselines.csv", summary)
    write_csv(OUT / "baseline_attack_detection.csv", detection)
    for d in detection:
        print(d)
    for s in summary:
        print(s["baseline"], s["total_ms_median"], s["public_bytes_median"], s["private_bytes_median"],
              s.get("ops_sig_verify_median"), s.get("ops_hash_median"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
