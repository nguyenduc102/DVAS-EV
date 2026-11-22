"""Authenticated binding between DR_private and the meter-signed DR_t."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

from dbas_et.dvas.delivery import h_priv_of, private_payload_bytes, resign
from dbas_et.dvas.evidence import EvidenceContext, seal_evidence
from dbas_et.dvas.profiles import ECDSA, Signer
from dbas_et.dvas.registry import Role

from ..conftest import ready


def _outcomes(s, req=None):
    return s.verify(req)


def _all_reject(outcomes, reason_prefix):
    return all((not o.ok) and o.reason.startswith(reason_prefix) for o in outcomes)


def test_honest_session_all_verifiers_attest(env, acn_specs):
    s = ready(env, acn_specs[0], verify=True)
    assert all(o.ok for o in s.outcomes)
    assert len({o.body.digest for o in s.outcomes}) == 1


def test_attacker_created_valid_kem_ciphertext(env, acn_specs):
    """Fresh, perfectly valid KEM+AEAD envelope sealed by the attacker for the right context."""
    s = ready(env, acn_specs[1])
    forged = dict(s.private_values, active_charging_duration_s=0, parking_duration_s=0,
                  session_ref="attacker-session")
    ctx = s.envelope.context
    s.envelope = seal_evidence(private_payload_bytes(forged), ctx, env.recipients())
    outs = _outcomes(s)
    assert _all_reject(outs, "PRIVATE_DIGEST_MISMATCH")
    assert all(o.stage == "6_h_priv" for o in outs)


def test_valid_public_receipt_with_substituted_genuine_private_payload(env, acn_specs):
    """Genuine DR_private from another session re-sealed under this session's context."""
    a = ready(env, acn_specs[2])
    b = ready(env, acn_specs[3])
    a.envelope = seal_evidence(private_payload_bytes(b.private_values), a.envelope.context, env.recipients())
    assert _all_reject(_outcomes(a), "PRIVATE_DIGEST_MISMATCH")


def test_private_payload_with_wrong_meter_receipt(env, acn_specs):
    """Envelope of session B presented with the meter receipt of session A."""
    a = ready(env, acn_specs[4])
    b = ready(env, acn_specs[5])
    a.envelope = b.envelope
    assert _all_reject(_outcomes(a), "PRIVATE_CONTEXT_MISMATCH")


def test_private_payload_digest_mismatch_relabelled_context(env, acn_specs):
    """Attacker rewrites the envelope context to claim this receipt's h_priv. AEAD fails."""
    a = ready(env, acn_specs[6])
    b = ready(env, acn_specs[7])
    a.envelope = replace(b.envelope, context=a.envelope.context)
    outs = _outcomes(a)
    assert all(not o.ok and o.stage == "4_private_open" for o in outs)


def test_receipt_h_priv_changed_breaks_meter_signature(env, acn_specs):
    s = ready(env, acn_specs[8])
    bad = s.receipt.with_values(h_priv=h_priv_of(dict(s.private_values, session_ref="x")))
    s.receipt = bad
    outs = _outcomes(s)
    assert _all_reject(outs, "BAD_METER_SIGNATURE")


def test_wrong_sid_root_tid_rejected_at_submit_and_verifier(env, acn_specs):
    for field, value, code in [("sid", "sid-other", "SID_MISMATCH"), ("rho_t", "ab" * 32, "RHO_MISMATCH")]:
        spec = acn_specs[9 if field == "sid" else 10]
        s = env.session(spec)
        s.commit(); s.authorize(); s.open_session()
        meter = s.meter
        rec = s.deliver()
        forged = resign(rec.with_values(**{field: value}), meter.signer)  # meter-signed but wrong context
        assert env.ledger.submit_receipt(forged).code == code
    s = ready(env, acn_specs[11])
    s.receipt = resign(s.receipt.with_values(receipt_tid="other-tid"), s.meter.signer)
    outs = _outcomes(s)
    assert all(not o.ok and o.stage == "3_binding" for o in outs)


def test_unregistered_meter_key(env, acn_specs):
    s = env.session(acn_specs[12])
    s.commit(); s.authorize(); s.open_session(); s.deliver()
    rogue = Signer(ECDSA)
    assert env.ledger.submit_receipt(resign(s.receipt, rogue)).code == "BAD_METER_SIGNATURE"


def test_revoked_meter_key(env, acn_specs):
    s = env.session(acn_specs[13])
    s.commit(); s.authorize(); s.open_session(); s.deliver()
    env.registry.revoke(s.spec.meter_id)
    assert env.ledger.submit_receipt(s.receipt).code == "METER_KEY_REVOKED"


def test_rotated_meter_old_epoch_is_stale(env, acn_specs):
    s = env.session(acn_specs[14])
    s.commit(); s.authorize(); s.open_session(); s.deliver()  # signed with epoch 1
    new = Signer(ECDSA)
    env.registry.rotate(s.spec.meter_id, new.public_key, new.scheme)
    assert env.ledger.submit_receipt(s.receipt).code == "METER_KEY_STALE_EPOCH"
    # after rotation the meter signs with the new key/epoch and is accepted
    s.meter.signer, s.meter.key_epoch = new, 2
    s.deliver()
    assert env.ledger.submit_receipt(s.receipt).ok


def test_revoked_meter_after_submit_rejected_by_verifiers(env, acn_specs):
    s = ready(env, acn_specs[15])
    env.registry.revoke(s.spec.meter_id)
    assert _all_reject(_outcomes(s), "METER_KEY_REVOKED")


def test_verifier_order_signature_before_decryption(env, acn_specs):
    """A bad meter signature is rejected before any KEM/AEAD work (step 2 before step 4)."""
    s = ready(env, acn_specs[16])
    s.receipt = resign(s.receipt, Signer(ECDSA))
    outs = _outcomes(s)
    assert all(o.stage == "2_meter_signature" and "private_open" not in o.timings_ms for o in outs)


def test_public_private_inconsistency_detected(env, acn_specs):
    """Meter-signed h_priv over a payload whose delivered energy differs from the public receipt."""
    s = env.session(acn_specs[17])
    s.commit(); s.authorize(); s.open_session()
    rec = s.deliver()
    priv = dict(s.private_values, delivered_kwh=s.private_values["delivered_kwh"] + Decimal("1"))
    hp = h_priv_of(priv)
    rec2 = resign(rec.with_values(h_priv=hp), s.meter.signer)
    env_ = seal_evidence(private_payload_bytes(priv), EvidenceContext(s.spec.tid, s.sid, rec["rho_t"],
                         s.spec.meter_id, hp), env.recipients())
    s.receipt, s.envelope = rec2, env_
    assert s.submit_receipt().ok
    assert _all_reject(_outcomes(s), "PUBLIC_PRIVATE_MISMATCH:delivered_kwh")


def test_legacy_accepts_attacker_payload_contrast():
    """Legacy KEM-AEAD path accepts a non-meter payload (documented in the baseline probe)."""
    import csv
    from pathlib import Path

    p = Path(__file__).resolve().parents[2] / "outputs" / "legacy_probe.csv"
    if p.exists():
        rows = {r["probe"]: r for r in csv.DictReader(open(p))}
        assert rows["P2_attacker_created_private_payload"]["weakness_present"] == "True"


def test_wrong_role_key_for_meter(env, acn_specs):
    s = env.session(acn_specs[18])
    s.commit(); s.authorize(); s.open_session(); s.deliver()
    # a verifier key is registered, but under the VERIFIER role, not the METER role
    sv = env.verifiers["SV1"]
    forged = resign(s.receipt.with_values(receipt_meter_id="SV1"), sv.signer)
    assert env.registry.lookup("SV1", Role.METER).reason == "WRONG_ROLE"
    assert not env.ledger.submit_receipt(forged).ok
