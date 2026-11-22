"""Private-evidence origin binding.

KEM+AEAD gives confidentiality and ciphertext integrity only: anyone holding
the verifiers' public KEM keys can produce an envelope that decrypts cleanly.
Origin binding comes from the meter signature over the public receipt, which
contains h_priv = H(canonical_encode(DR_private)).  Each test shows which layer
accepts and which layer rejects.
"""

from __future__ import annotations

from dbas_et.dvas.delivery import h_priv_of, private_payload_bytes, resign
from dbas_et.dvas.evidence import EvidenceContext, open_evidence, seal_evidence
from dbas_et.dvas.profiles import ECDSA, Signer, verify_signature
from dbas_et.dvas.registry import Role

from ..conftest import ready


def _aead_layer_ok(env, s) -> bool:
    """Does the envelope open for SV1 at the KEM+AEAD layer (ignoring origin)?"""
    sv = env.verifiers["SV1"]
    r = s.receipt
    ctx = EvidenceContext(s.spec.tid, r["sid"], r["rho_t"], r["receipt_meter_id"], r["h_priv"])
    return open_evidence(s.envelope, verifier_id="SV1", kem_epoch=sv.kem_epoch, kem_keypair=sv.kem, expected=ctx).ok


def _stages(s):
    return {o.stage for o in s.verify()}, {o.reason for o in s.outcomes}


def test_honest_evidence_passes_both_layers(env, acn_specs):
    s = ready(env, acn_specs[0])
    assert _aead_layer_ok(env, s)
    sv = env.verifiers["SV1"]
    pt = open_evidence(s.envelope, verifier_id="SV1", kem_epoch=1, kem_keypair=sv.kem, expected=s.envelope.context).plaintext
    assert h_priv_of(pt) == s.receipt["h_priv"]
    assert all(o.ok for o in s.verify())


def test_attacker_created_valid_kem_aead_ciphertext_is_insufficient(env, acn_specs):
    s = ready(env, acn_specs[1])
    forged = dict(s.private_values, active_charging_duration_s=0, session_ref="attacker")
    s.envelope = seal_evidence(private_payload_bytes(forged), s.envelope.context, env.recipients())
    assert _aead_layer_ok(env, s), "confidentiality/integrity layer accepts the attacker's ciphertext"
    stages, reasons = _stages(s)
    assert stages == {"6_h_priv"} and reasons == {"PRIVATE_DIGEST_MISMATCH"}, "origin binding rejects it"


def test_substituted_private_payload_fails_h_priv(env, acn_specs):
    a, b = ready(env, acn_specs[2]), ready(env, acn_specs[3])
    a.envelope = seal_evidence(private_payload_bytes(b.private_values), a.envelope.context, env.recipients())
    assert _aead_layer_ok(env, a)
    assert _stages(a) == ({"6_h_priv"}, {"PRIVATE_DIGEST_MISMATCH"})


def test_valid_public_receipt_with_wrong_private_evidence(env, acn_specs):
    a, b = ready(env, acn_specs[4]), ready(env, acn_specs[5])
    a.envelope = b.envelope  # genuine envelope of another session
    assert verify_signature(ECDSA, env.meters[a.spec.meter_id].signer.public_key, a.receipt.message(), a.receipt.signature)
    stages, reasons = _stages(a)
    assert stages == {"4_private_open"} and reasons == {"PRIVATE_CONTEXT_MISMATCH"}


def test_wrong_meter_signature(env, acn_specs):
    s = ready(env, acn_specs[6])
    s.receipt = resign(s.receipt, Signer(ECDSA))
    assert _aead_layer_ok(env, s)
    assert _stages(s) == ({"2_meter_signature"}, {"BAD_METER_SIGNATURE"})


def test_wrong_tid_sid_rho(env, acn_specs):
    for i, (field, value) in enumerate([("receipt_tid", "T_OTHER"), ("sid", "S_OTHER"), ("rho_t", "ab" * 32)]):
        s = ready(env, acn_specs[7 + i])
        s.receipt = resign(s.receipt.with_values(**{field: value}), s.meter.signer)  # meter-signed, wrong context
        stages, _ = _stages(s)
        assert stages == {"3_binding"}, (field, stages)


def test_revoked_and_stale_meter_keys(env, acn_specs):
    s = ready(env, acn_specs[10])
    env.registry.revoke(s.spec.meter_id)
    assert _stages(s)[1] == {"METER_KEY_REVOKED"}
    s2 = ready(env, next(sp for sp in acn_specs[11:] if sp.meter_id != s.spec.meter_id))
    new = Signer(ECDSA)
    env.registry.rotate(s2.spec.meter_id, new.public_key, new.scheme)
    assert env.registry.lookup(s2.spec.meter_id, Role.METER, epoch=1).reason == "STALE_EPOCH"
    assert _stages(s2)[1] == {"METER_KEY_STALE_EPOCH"}


def test_h_priv_is_inside_the_meter_signature(env, acn_specs):
    s = ready(env, acn_specs[12])
    m = env.meters[s.spec.meter_id].signer
    tampered = s.receipt.with_values(h_priv=h_priv_of(dict(s.private_values, session_ref="x")))
    assert not verify_signature(ECDSA, m.public_key, tampered.message(), tampered.signature)
