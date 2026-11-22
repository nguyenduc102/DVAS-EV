"""Quorum cost evaluation -> outputs/quorum_cost.csv.

Compares the legacy single SettlementVerifier (dbas_et.settlement_verifier +
SettleSC.release_settlement_with_certificate, ML-KEM protected payload, OQS)
with DVAS-EV 1-of-1, 2-of-3 and 3-of-5 (profile C3).

Scope: local protocol-processing latency (single Python process, verifiers run
sequentially; critical path = slowest verifier + aggregation + settlement).
Gas = gasleft() delta inside Foundry tests (outputs/solidity_gas.csv).
Transaction inclusion and end-to-end charging latency are not measured.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, ROOT, SCOPE, stats, write_csv, write_metadata  # noqa: E402

from dbas_et.dvas.attacks import unique  # noqa: E402
from dbas_et.dvas.profiles import PROFILES  # noqa: E402
from dbas_et.dvas.protocol import DvasEnvironment  # noqa: E402
from dbas_et.dvas.workload import acn_sessions  # noqa: E402


def gas_table() -> dict[str, int]:
    p = OUT / "solidity_gas.csv"
    if not p.exists():
        return {}
    out = {}
    for r in csv.DictReader(open(p)):
        key = r["measurement"] if r.get("contract_suite") == "DVASQuorumSettle" else f"legacy:{r['measurement']}"
        out[key] = int(r["gas"])
    return out


def legacy(n: int, warmup: int) -> list[dict]:
    sys.path.insert(0, str(ROOT / "scripts"))
    import benchmark_common as bc
    from dbas_et.capsule import capsule_to_semantic_layout
    from dbas_et.crypto import canonical_dumps, gen_ec_keypair
    from dbas_et.payments import build_delivery_receipt, build_session_id
    from dbas_et.protected_flow import generate_protected_flow_recipient, protect_protocol_payload
    from dbas_et.settlement_verifier import SettlementVerifier

    df = bc.load_profile_csv(ROOT / "data/acn/processed/profile_valid_preauthorization.csv", max_rows=n + warmup)
    env = bc.build_benchmark_environment(df, pq_backend="oqs", kem_backend="oqs", strict_pq=True)
    kem, sk = generate_protected_flow_recipient(kem_backend="oqs", strict_pq=True), gen_ec_keypair()
    sv = SettlementVerifier(verifier_id="SV_LEGACY", sign_sk=sk.sk, sign_pk=sk.pk, kem_keys=kem)
    rows = []
    for idx, row in df.iterrows():
        user, station, meter = (env.users[row["protocol_user_id"]], env.stations[row["protocol_station_id"]],
                                env.meters[row["protocol_meter_id"]])
        cap = bc.capsule_from_workload_row(row, user, station, meter, int(idx))
        art = env.backend.commit_layout(capsule_to_semantic_layout(cap))
        A_view, A_proof = env.backend.open_projection(art, "A")
        S_view, S_proof = env.backend.open_projection(art, "S")
        assert env.authsc.authorize_trade(user=user, capsule=cap, rho_t=art.rho_t, A_view=A_view, A_proof=A_proof,
                                          backend=env.backend).ok
        sid = build_session_id(cap, nonce=f"qc-{idx}", rho_t=art.rho_t)
        assert env.settlesc.open_session(cap.trade_id, sid).ok
        rc = build_delivery_receipt(capsule=cap, sid_t=sid, meter=meter, delivered_kwh=float(row["delivered_kwh"]),
                                    ts_start=int(row["tw_start"]), ts_end=int(row["tw_end"]), tariff_mode=cap.tariff_mode,
                                    connection_duration_s=int(row["connection_duration_s"]),
                                    active_charging_duration_s=int(row["active_charging_duration_s"]),
                                    parking_duration_s=int(row["parking_duration_s"]), nonce_m=f"qc-m-{idx}")
        assert env.settlesc.submit_receipt(rc).ok
        pp = protect_protocol_payload(payload_type="DeliveryReceiptPrivate", phase="delivery_receipt",
                                      trade_id=cap.trade_id, rho_t=art.rho_t, sid_t=sid, sender_id=meter.meter_id,
                                      recipient_id=sv.verifier_id, recipient_role="settlement_verifier",
                                      recipient_kem_pk=kem.pk, recipient_pkid=kem.pkid, kem_backend="oqs",
                                      payload={"delivered_kwh": rc.delivered_kwh, "start_time": rc.ts_start,
                                               "end_time": rc.ts_end})
        rec = env.authsc.records[cap.trade_id].to_record()
        ar = dict(rec, _auth_record=rec, unit_price=cap.unit_price, tariff_id=cap.tariff_id,
                  tariff_version=cap.tariff_version, tw_start=cap.tw_start, tw_end=cap.tw_end, cap_kwh=cap.cap_kwh)
        t0 = time.perf_counter()
        out = sv.verify_and_issue_rbc(ar_t=ar, receipt=rc, meter=meter, rho_t=art.rho_t, S_view=S_view, S_proof=S_proof,
                                      backend=env.backend, meter_samples=[], tariff_record={}, protected_payloads=[pp])
        t1 = time.perf_counter()
        rel = env.settlesc.release_settlement_with_certificate(rbc_public=out.value.rbc_public, verifier=sv, user=user)
        t2 = time.perf_counter()
        assert rel.ok
        if idx >= warmup:
            rows.append({"verify_ms": (t1 - t0) * 1000, "settle_ms": (t2 - t1) * 1000,
                         "rbc_bytes": len(canonical_dumps(out.value.rbc_public.to_record())), "signatures": 1})
    return rows


def dvas(n: int, warmup: int, nn: int, t: int) -> list[dict]:
    env = DvasEnvironment(profile=PROFILES["C3"], n=nn, t=t)
    specs = acn_sessions(max_rows=n + warmup)
    rows = []
    for i, sp in enumerate(specs):
        r = env.run(unique(sp, f"qc:{nn}"))
        assert r.ok
        if i >= warmup:
            tm = r.timings_ms
            per = [o.timings_ms["total"] for o in r.verifier_outcomes]
            rows.append({"verify_ms": stats(per)["median"], "verify_max_ms": tm["verifiers_max"],
                         "verify_sum_ms": tm["verifiers_sum"], "aggregate_ms": tm["rbc_aggregate"],
                         "settle_ms": tm["settle"], "rbc_bytes": r.sizes["rbc_bytes"], "signatures": t})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=200)
    ap.add_argument("--warmup", type=int, default=20)
    a = ap.parse_args()
    write_metadata("quorum_cost")
    gas = gas_table()
    fm = {(r["config"], r["malicious_colluding"], r["offline"], r["goal"]): r
          for r in csv.DictReader(open(OUT / "quorum_fault_matrix.csv"))} if (OUT / "quorum_fault_matrix.csv").exists() else {}
    out = []
    L = legacy(a.sessions, a.warmup)
    out.append({"config": "legacy single SettlementVerifier", "verifiers": 1, "threshold": 1,
                "per_verifier_ms_median": round(stats([r["verify_ms"] for r in L])["median"], 4),
                "critical_path_ms_median": round(stats([r["verify_ms"] + r["settle_ms"] for r in L])["median"], 4),
                "critical_path_ms_p95": round(stats([r["verify_ms"] + r["settle_ms"] for r in L])["p95"], 4),
                "total_verifier_cpu_ms_median": round(stats([r["verify_ms"] for r in L])["median"], 4),
                "settle_ms_median": round(stats([r["settle_ms"] for r in L])["median"], 4),
                "rbc_bytes_median": stats([r["rbc_bytes"] for r in L])["median"], "signatures_in_rbc": 1,
                "gas_release": gas.get("legacy:releaseByRBC", ""),
                "settles_with_1_offline": "no (single verifier)", "safe_with_1_malicious": "no (probe P3: inflated capture accepted)",
                "rbc_size_note": "JSON record", "scope": SCOPE})
    for nn, t in [(1, 1), (3, 2), (5, 3)]:
        D = dvas(a.sessions, a.warmup, nn, t)
        cfg = f"{t}-of-{nn}"
        one_off = fm.get((cfg, "0", "1", "inflate_valid"))
        one_mal = fm.get((cfg, "1", "0", "inflate_valid"))
        out.append({"config": f"DVAS-EV {cfg}", "verifiers": nn, "threshold": t,
                    "per_verifier_ms_median": round(stats([r["verify_ms"] for r in D])["median"], 4),
                    "critical_path_ms_median": round(stats([r["verify_max_ms"] + r["aggregate_ms"] + r["settle_ms"] for r in D])["median"], 4),
                    "critical_path_ms_p95": round(stats([r["verify_max_ms"] + r["aggregate_ms"] + r["settle_ms"] for r in D])["p95"], 4),
                    "total_verifier_cpu_ms_median": round(stats([r["verify_sum_ms"] for r in D])["median"], 4),
                    "settle_ms_median": round(stats([r["settle_ms"] for r in D])["median"], 4),
                    "rbc_bytes_median": stats([r["rbc_bytes"] for r in D])["median"], "signatures_in_rbc": t,
                    "gas_release": gas.get(f"releaseByQuorumRBC_{t}of{nn}", ""),
                    "settles_with_1_offline": ("no" if nn == 1 else f"{one_off['correct']}/{one_off['sessions']}") if (one_off or nn == 1) else "n/a",
                    "safe_with_1_malicious": ("no (t=1)" if nn == 1 else f"{one_mal['correct']}/{one_mal['sessions']} correct") if (one_mal or nn == 1) else "n/a",
                    "rbc_size_note": "canonical body + attestations", "scope": SCOPE})
        print(json.dumps(out[-1], default=str))
    print(json.dumps(out[0], default=str))
    write_csv(OUT / "quorum_cost.csv", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
