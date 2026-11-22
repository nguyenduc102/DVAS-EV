"""Legacy regression (R1-R5): the earlier DBAS-ET prototype vs DVAS-EV.

Each case is run on the unchanged legacy code path and on the DVAS-EV path.  Output: <OUT>/legacy_regression.csv with
issue_id, description, legacy_result, dvas_result, expected_result, pass.

pass = the DVAS-EV result equals the expected (safe) result.  The legacy column
shows the weakness of the earlier design.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_env import OUT, ROOT, write_csv, write_metadata  # noqa: E402

import probe_legacy_weaknesses as legacy_probe  # noqa: E402  (unchanged legacy setup helpers)

from dbas_et.dvas.attacks import unique  # noqa: E402
from dbas_et.dvas.delivery import private_payload_bytes  # noqa: E402
from dbas_et.dvas.evidence import seal_evidence  # noqa: E402
from dbas_et.dvas.pam import open_fields, verify_opening  # noqa: E402
from dbas_et.dvas.predicates import evaluate, predicate_for, required_fields  # noqa: E402
from dbas_et.dvas.profiles import PROFILES  # noqa: E402
from dbas_et.dvas.protocol import DvasEnvironment  # noqa: E402
from dbas_et.dvas.schema import LAYOUT_V1  # noqa: E402
from dbas_et.dvas.workload import ACN_ORIGINAL_CAP, acn_sessions, honest_amount  # noqa: E402


def _ready(env, spec, **deliver):
    s = env.session(spec)
    s.commit(); assert s.authorize().ok; assert s.open_session().ok
    s.deliver(**deliver)
    return s


def r1(spec):
    """Authentic Merkle opening missing a required predicate field (over-cap delivery, cap omitted)."""
    ctx = legacy_probe._setup(delivered_kwh=12.0)
    ar = {k: v for k, v in ctx["ar_full"].items() if k != "cap_kwh"}
    leg_sv = legacy_probe._issue(ctx, ar, []).value.rbc_public.predicate_result
    env = DvasEnvironment(profile=PROFILES["C3"])
    sp = replace(spec, delivered_kwh=spec.cap_kwh + Decimal("2"))
    s = _ready(env, sp)
    assert s.submit_receipt().ok
    req = required_fields(LAYOUT_V1, "settlement")
    op = open_fields(s.commitment, [n for n in req if n != "cap_kwh"], reason="settlement")
    pam = verify_opening(s.commitment.rho_t, op, reason="settlement").code
    outs = s.verify(s.settlement_request(op))
    settled = s.aggregate() is not None
    return ("ACCEPTED (legacy Match defaults cap_kwh; over-cap RBC issued)" if leg_sv else "REJECTED",
            f"REJECTED ({pam}; verifiers: {sorted({o.reason for o in outs})}; settled={settled})", not settled and pam == "INCOMPLETE_OPENING")


def r2(spec):
    """Attacker-generated valid KEM+AEAD private ciphertext, not bound to the meter."""
    ctx = legacy_probe._setup(delivered_kwh=8.0)
    rc = ctx["receipt"]
    forged = legacy_probe._pp(ctx, {"delivered_kwh": rc.delivered_kwh, "start_time": rc.ts_start, "end_time": rc.ts_end,
                                    "tariff_id": rc.tariff_id, "tariff_version": rc.tariff_version,
                                    "injected_by": "attacker"}, sender="ATTACKER")
    leg = legacy_probe._issue(ctx, ctx["ar_full"], [forged]).value.rbc_public.predicate_result
    env = DvasEnvironment(profile=PROFILES["C3"])
    s = _ready(env, spec)
    s.envelope = seal_evidence(private_payload_bytes(dict(s.private_values, session_ref="attacker")),
                               s.envelope.context, env.recipients())
    assert s.submit_receipt().ok
    outs = s.verify()
    reasons = sorted({o.reason for o in outs})
    ok = all(not o.ok for o in outs) and reasons == ["PRIVATE_DIGEST_MISMATCH"]
    return ("ACCEPTED (no origin binding)" if leg else "REJECTED", f"REJECTED ({reasons})", ok)


def r3(spec):
    """Single malicious verifier signs an inflated semantic decision."""
    from dataclasses import replace as dreplace

    from dbas_et.crypto import H, ecdsa_sign

    ctx = legacy_probe._setup(delivered_kwh=8.0)
    rbc = legacy_probe._issue(ctx, ctx["ar_full"], []).value.rbc_public
    infl = dreplace(rbc, captured_amount=9.99)
    infl = dreplace(infl, verifier_signature_hex=ecdsa_sign(ctx["sv"].sign_sk, H("DBAS-ET:RBC-PUBLIC-TO-SIGN:v1", infl.unsigned_record())).hex())
    leg = ctx["settle"].release_settlement_with_certificate(rbc_public=infl, verifier=ctx["sv"], user=ctx["user"])
    env = DvasEnvironment(profile=PROFILES["C3"], behaviors={"SV2": "inflate"})
    r = env.run(spec)
    ok = r.ok and r.captured == honest_amount(spec)
    return (f"{'ACCEPTED' if leg.ok else 'REJECTED'} (single SV; captured {leg.value.captured_amount if leg.ok else '-'} for a 4.0 delivery)",
            f"SETTLED CORRECT AMOUNT {r.captured} (2-of-3, SV2 inflate excluded)", ok)


def r4():
    """Capture exceeds hold by floating-point tolerance (ACN original-cap row 2320)."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import benchmark_common as bc

    df = bc.load_profile_csv(ACN_ORIGINAL_CAP).iloc[[2320]].reset_index(drop=True)
    env_l = bc.build_benchmark_environment(df, pq_backend="oqs", kem_backend="oqs", strict_pq=True)
    rec, _ = bc.run_one_workload_row(env_l, df.iloc[0], 2320, "original_cap")
    spec = acn_sessions(ACN_ORIGINAL_CAP, max_rows=2321)[2320]
    r = DvasEnvironment(profile=PROFILES["C3"]).run(spec)
    leg = (f"{'ACCEPTED' if rec.get('settlement_ok') else 'REJECTED'} (captured {rec.get('captured_amount')} vs hold "
           f"{spec.preauth_limit}; MONEY_EPS=1e-5)")
    return leg, f"{'SETTLED' if r.ok else 'REJECTED'} ({r.code[:80]})", (not r.ok) and "amount_within_effective_limit" in r.code


def r5():
    """Missing predicate operand receives no default value."""
    from dbas_et.payments import DeliveryReceipt
    from dbas_et.projections import ProjectionView
    from dbas_et.settlement_verifier import evaluate_match_checks

    rc = DeliveryReceipt(trade_id="t", sid_t="s", station_id="S", meter_id="M", foreign_domain="OF", delivered_kwh=12.0,
                         ts_start=110, ts_end=190, tariff_id="T", tariff_version="v1", tariff_mode="ENERGY_ONLY")
    ar = {"trade_id": "t", "rho_t": "r", "station_id": "S", "meter_id": "M", "tariff_id": "T", "tariff_version": "v1",
          "tw_start": 100, "tw_end": 200, "unit_price": 0.5, "effective_preauth_limit_t": 10}
    checks, _ = evaluate_match_checks(ar_t=ar, receipt=rc, rho_t="r", S_view=ProjectionView("S", "t", []),
                                      meter_samples=[], tariff_record={}, opened_payloads={})
    committed = {"tid": "t", "station_id": "S", "meter_id": "M", "foreign_operator": "OF", "beneficiary": "B",
                 "tariff_id": "T", "tariff_version": "v1", "tariff_mode": "ENERGY_ONLY", "unit_price": Decimal("0.5"),
                 "currency": "TOKEN", "preauth_limit": Decimal("10"), "tw_start": 100, "tw_end": 200, "paytok": "p"}
    ev = {"receipt_tid": "t", "receipt_station_id": "S", "receipt_meter_id": "M", "applied_tariff_id": "T",
          "applied_tariff_version": "v1", "settlement_currency": "TOKEN", "delivered_kwh": Decimal("12"), "ts_start": 110,
          "ts_end": 190, "connection_duration_s": 80, "active_charging_duration_s": 80, "parking_duration_s": 0,
          "effective_limit": Decimal("10"), "held_amount": Decimal("10"), "payee": "B", "ledger_paytok": "p"}
    rel = {"meter_bound_to_station": lambda m, s: True, "station_operated_by": lambda s, o: True}
    res = evaluate(predicate_for("settlement"), committed, ev, rel)  # cap_kwh absent
    leg = "ACCEPTED (cap_kwh defaulted to delivered_kwh)" if all(checks.values()) else "REJECTED"
    return leg, f"REJECTED ({res.reason})", (not res.ok) and "committed:cap_kwh" in res.missing


def main() -> int:
    write_metadata("legacy_regression")
    spec = unique(acn_sessions(max_rows=1)[0], "legacy")
    issues = [
        ("R1", "authentic Merkle opening missing a required predicate field", lambda: r1(spec)),
        ("R2", "attacker-generated valid KEM+AEAD private ciphertext not bound to the meter", lambda: r2(unique(spec, "r2"))),
        ("R3", "single malicious verifier signs an inflated semantic decision", lambda: r3(unique(spec, "r3"))),
        ("R4", "capture exceeds hold by floating-point tolerance", r4),
        ("R5", "missing predicate operand receives no default value", r5),
    ]
    expected = {"R1": "REJECTED", "R2": "REJECTED", "R3": "SETTLED WITH HONEST AMOUNT", "R4": "REJECTED", "R5": "REJECTED"}
    rows = []
    for iid, desc, fn in issues:
        leg, rev, ok = fn()
        rows.append({"issue_id": iid, "description": desc, "legacy_result": leg, "dvas_result": rev,
                     "expected_result": expected[iid], "pass": bool(ok)})
        print(iid, "PASS" if ok else "FAIL", "| legacy:", leg, "| dvas:", rev)
    write_csv(OUT / "legacy_regression.csv", rows)
    return 0 if all(r["pass"] for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
