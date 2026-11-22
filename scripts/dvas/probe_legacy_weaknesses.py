"""Probe the legacy DBAS-ET code for the weaknesses fixed in DVAS-EV.

This script does not modify any legacy module.  It demonstrates, on the
unchanged legacy settlement path, whether:

  P1  a predicate-incomplete settlement context is accepted
      (legacy Match silently defaults a missing operand),
  P1b a field-level Merkle opening that omits a predicate operand verifies
  P2  a private payload created by a party other than the meter is accepted
      (KEM+AEAD gives confidentiality/integrity, not sender authentication),
  P2b settlement proceeds with no private payload at all
  P3  a single (malicious) SettlementVerifier can authorise an inflated capture.

Output: outputs/legacy_probe.csv
"""

from __future__ import annotations

import csv
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dbas_et.capsule import build_demo_capsule, capsule_to_semantic_layout  # noqa: E402
from dbas_et.contracts import AuthSC, RegSC, SettleSC  # noqa: E402
from dbas_et.crypto import H, ecdsa_sign, gen_ec_keypair  # noqa: E402
from dbas_et.entities import create_meter, create_station, create_user  # noqa: E402
from dbas_et.field_merkle import V2FieldMerkleSettlementBackend  # noqa: E402
from dbas_et.mspc import compile_projection  # noqa: E402
from dbas_et.payments import build_delivery_receipt, build_session_id  # noqa: E402
from dbas_et.projections import V2SlimSettlementBackend  # noqa: E402
from dbas_et.protected_flow import generate_protected_flow_recipient, protect_protocol_payload  # noqa: E402
from dbas_et.settlement_verifier import SettlementVerifier  # noqa: E402


def _setup(delivered_kwh: float, cap_kwh: float = 10.0, limit: float = 10.0):
    user = create_user("U_P", balance=100.0, pq_backend="oqs", strict_pq=True)
    station = create_station("S_P", strict_pq=True)
    meter = create_meter("M_P", station_id=station.station_id, foreign_domain=station.foreign_domain)
    reg = RegSC(); reg.register_user(user); reg.register_station(station); reg.register_meter(meter)
    auth = AuthSC(reg); settle = SettleSC(reg, auth); backend = V2SlimSettlementBackend()
    capsule = build_demo_capsule(user=user, station=station, meter=meter, requested_kwh=8.0,
                                 delivered_cap_kwh=cap_kwh, preauth_limit_t=limit, unit_price=0.5)
    art = backend.commit_layout(capsule_to_semantic_layout(capsule))
    A_view, A_proof = backend.open_projection(art, "A")
    S_view, S_proof = backend.open_projection(art, "S")
    assert auth.authorize_trade(user=user, capsule=capsule, rho_t=art.rho_t, A_view=A_view,
                                A_proof=A_proof, backend=backend).ok
    sid = build_session_id(capsule, nonce="probe", rho_t=art.rho_t)
    assert settle.open_session(capsule.trade_id, sid).ok
    receipt = build_delivery_receipt(capsule=capsule, sid_t=sid, meter=meter, delivered_kwh=delivered_kwh,
                                     ts_start=capsule.tw_start + 10, ts_end=capsule.tw_start + 3600)
    assert settle.submit_receipt(receipt).ok
    kem = generate_protected_flow_recipient(kem_backend="oqs", strict_pq=True)
    sk = gen_ec_keypair()
    sv = SettlementVerifier(verifier_id="SV_P", sign_sk=sk.sk, sign_pk=sk.pk, kem_keys=kem)
    rec = auth.records[capsule.trade_id].to_record()
    ar_full = dict(rec, _auth_record=rec, unit_price=capsule.unit_price, tariff_id=capsule.tariff_id,
                   tariff_version=capsule.tariff_version, tw_start=capsule.tw_start, tw_end=capsule.tw_end,
                   cap_kwh=capsule.cap_kwh)
    return dict(user=user, meter=meter, settle=settle, backend=backend, capsule=capsule, art=art,
                S_view=S_view, S_proof=S_proof, sid=sid, receipt=receipt, sv=sv, ar_full=ar_full)


def _pp(ctx, payload, sender="M_P"):
    sv = ctx["sv"]
    return protect_protocol_payload(
        payload_type="DeliveryReceiptPrivate", phase="delivery_receipt", trade_id=ctx["capsule"].trade_id,
        rho_t=ctx["art"].rho_t, sid_t=ctx["sid"], sender_id=sender, recipient_id=sv.verifier_id,
        recipient_role="settlement_verifier", recipient_kem_pk=sv.kem_keys.pk, recipient_pkid=sv.kem_keys.pkid,
        kem_backend="oqs", payload=payload)


def _issue(ctx, ar_t, payloads):
    return ctx["sv"].verify_and_issue_rbc(
        ar_t=ar_t, receipt=ctx["receipt"], meter=ctx["meter"], rho_t=ctx["art"].rho_t, S_view=ctx["S_view"],
        S_proof=ctx["S_proof"], backend=ctx["backend"], meter_samples=[], tariff_record={},
        protected_payloads=payloads)


def main() -> int:
    rows = []

    # P1: over-cap receipt (12 kWh > cap 10) with cap_kwh omitted from the verifier context.
    ctx = _setup(delivered_kwh=12.0)
    honest = _issue(ctx, ctx["ar_full"], [])
    ar_missing_cap = {k: v for k, v in ctx["ar_full"].items() if k != "cap_kwh"}
    res = _issue(ctx, ar_missing_cap, [])
    rows.append(dict(probe="P1_missing_cap_operand_overcap",
                     description="over-cap receipt; cap_kwh operand missing from Match context",
                     control_predicate=honest.value.rbc_public.predicate_result,
                     legacy_predicate_result=res.value.rbc_public.predicate_result,
                     weakness_present=bool(res.value.rbc_public.predicate_result)))

    # P1b: field-level opening omitting a required settlement operand still verifies.
    fm = V2FieldMerkleSettlementBackend()
    layout = capsule_to_semantic_layout(ctx["capsule"])
    fart = fm.commit_layout(layout)
    plan = compile_projection(layout, "S", candidate_mode="field", objective="proof_size")
    drop = "S.settlement_terms.cap_kwh"
    reduced = replace(plan, disclosed_fields=tuple(f for f in plan.disclosed_fields if f != drop))
    view, proof, _ = fm.open_projection(fart, "S", plan=reduced)
    ok = fm.verify_projection(fart.rho_t, view, proof)
    rows.append(dict(probe="P1b_opening_omits_cap_kwh", description=f"S opening without {drop}",
                     control_predicate="", legacy_predicate_result=ok, weakness_present=bool(ok)))

    # P2: attacker-created private payload (only needs SV public KEM key).
    ctx = _setup(delivered_kwh=8.0)
    r = ctx["receipt"]
    forged = _pp(ctx, {"delivered_kwh": r.delivered_kwh, "start_time": r.ts_start, "end_time": r.ts_end,
                       "tariff_id": r.tariff_id, "tariff_version": r.tariff_version,
                       "injected_by": "attacker", "meter_values": [{"kwh": 999}]}, sender="ATTACKER")
    res = _issue(ctx, ctx["ar_full"], [forged])
    rows.append(dict(probe="P2_attacker_created_private_payload",
                     description="KEM-AEAD payload sealed by non-meter party with fabricated extra evidence",
                     control_predicate="", legacy_predicate_result=res.value.rbc_public.predicate_result,
                     weakness_present=bool(res.value.rbc_public.predicate_result)))
    res2 = _issue(ctx, ctx["ar_full"], [])
    rows.append(dict(probe="P2b_no_private_payload", description="settlement with no private evidence at all",
                     control_predicate="", legacy_predicate_result=res2.value.rbc_public.predicate_result,
                     weakness_present=bool(res2.value.rbc_public.predicate_result)))

    # P3: one malicious SV signs an inflated capture (8 kWh * 0.5 = 4.0 -> claims 9.99).
    ctx = _setup(delivered_kwh=8.0)
    rbc = _issue(ctx, ctx["ar_full"], []).value.rbc_public
    inflated = replace(rbc, captured_amount=9.99)
    sig = ecdsa_sign(ctx["sv"].sign_sk, H("DBAS-ET:RBC-PUBLIC-TO-SIGN:v1", inflated.unsigned_record()))
    inflated = replace(inflated, verifier_signature_hex=sig.hex())
    rel = ctx["settle"].release_settlement_with_certificate(rbc_public=inflated, verifier=ctx["sv"], user=ctx["user"])
    rows.append(dict(probe="P3_single_malicious_sv_inflated_capture",
                     description="single SV signs captured_amount=9.99 for a 4.0 delivery",
                     control_predicate=4.0, legacy_predicate_result=rel.ok, weakness_present=bool(rel.ok)))

    out = ROOT / "outputs" / "legacy_probe.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    for row in rows:
        print(row)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
