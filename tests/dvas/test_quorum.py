"""Quorum settlement verification and quorum RBC checks."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

import pytest

from dbas_et.dvas.ledger import QuorumPolicy
from dbas_et.dvas.profiles import PROFILES, Signer
from dbas_et.dvas.protocol import DvasEnvironment
from dbas_et.dvas.rbc import QuorumRBC, RBCBody, VerificationAttestation, attestation_message

from ..conftest import ready


def _att(env, vid, body):
    n = env.verifiers[vid]
    sig = n.signer.sign(attestation_message(vid, n.key_epoch, body.digest))
    return VerificationAttestation.for_body(body, vid, n.key_epoch, sig, n.signer.scheme)


def _honest(env, spec):
    s = ready(env, spec, verify=True)
    assert all(o.ok for o in s.outcomes)
    return s, s.outcomes[0].body, {o.verifier_id: o.attestation for o in s.outcomes}


def _resign_body(body: RBCBody, **kw) -> RBCBody:
    return RBCBody.build(**{**body.values, **kw})


def test_1_of_3_rejected(env, acn_specs):
    s, body, att = _honest(env, acn_specs[0])
    assert env.ledger.settle(QuorumRBC(body, (att["SV1"],))).code == "BELOW_THRESHOLD"


def test_2_of_3_accepted(env, acn_specs):
    s, body, att = _honest(env, acn_specs[1])
    r = env.ledger.settle(QuorumRBC(body, (att["SV1"], att["SV3"])))
    assert r.ok and r.value["captured"] == s.spec.expected_amount


def test_3_of_3_accepted(env, acn_specs):
    s, body, att = _honest(env, acn_specs[2])
    assert env.ledger.settle(QuorumRBC(body, tuple(att.values()))).ok


def test_duplicate_signature_same_verifier(env, acn_specs):
    s, body, att = _honest(env, acn_specs[3])
    dup = _att(env, "SV1", body)  # fresh (different) ECDSA signature from the same verifier
    assert env.ledger.settle(QuorumRBC(body, (att["SV1"], dup))).code == "DUPLICATE_VERIFIER"
    assert env.ledger.settle(QuorumRBC(body, (att["SV1"], att["SV1"]))).code == "DUPLICATE_VERIFIER"


def test_unknown_verifier(env, acn_specs):
    s, body, att = _honest(env, acn_specs[4])
    rogue = Signer(env.profile.verifier_sig)
    sig = rogue.sign(attestation_message("SV_ROGUE", 1, body.digest))
    a = VerificationAttestation.for_body(body, "SV_ROGUE", 1, sig, rogue.scheme)
    assert env.ledger.settle(QuorumRBC(body, (att["SV1"], a))).code == "VERIFIER_KEY_UNREGISTERED"


def test_impersonated_verifier_signature(env, acn_specs):
    s, body, att = _honest(env, acn_specs[5])
    rogue = Signer(env.profile.verifier_sig)
    sig = rogue.sign(attestation_message("SV2", 1, body.digest))
    a = VerificationAttestation.for_body(body, "SV2", 1, sig, rogue.scheme)
    assert env.ledger.settle(QuorumRBC(body, (att["SV1"], a))).code == "BAD_VERIFIER_SIGNATURE"


def test_revoked_verifier_after_attestation_stale_set(env, acn_specs):
    s, body, att = _honest(env, acn_specs[6])
    env.registry.revoke("SV2")
    assert env.ledger.settle(QuorumRBC(body, (att["SV1"], att["SV2"]))).code == "STALE_VERIFIER_SET"


def test_different_decision_digests(env, acn_specs):
    s, body, att = _honest(env, acn_specs[7])
    other = _resign_body(body, captured_amount=body.captured - Decimal("0.01"),
                         refund_amount=body["refund_amount"] + Decimal("0.01"))
    a2 = _att(env, "SV2", other)
    assert env.ledger.settle(QuorumRBC(body, (att["SV1"], a2))).code == "DECISION_DIGEST_MISMATCH"


def test_signatures_from_different_roots(env, acn_specs):
    s, body, att = _honest(env, acn_specs[8])
    wrong = _resign_body(body, settle_rho_t="ee" * 32)
    rbc = QuorumRBC(wrong, (_att(env, "SV1", wrong), _att(env, "SV2", wrong)))
    assert env.ledger.settle(rbc).code == "WRONG_ROOT"
    assert env.ledger.settle(QuorumRBC(body, (att["SV1"], _att(env, "SV2", wrong)))).code == "DECISION_DIGEST_MISMATCH"


def test_wrong_transaction_or_session(env, acn_specs):
    a, body_a, att_a = _honest(env, acn_specs[9])
    b, body_b, att_b = _honest(env, acn_specs[10])
    wrong_sid = _resign_body(body_a, settle_sid=b.sid)
    rbc = QuorumRBC(wrong_sid, (_att(env, "SV1", wrong_sid), _att(env, "SV2", wrong_sid)))
    assert env.ledger.settle(rbc).code == "WRONG_SESSION"
    # attestations for transaction B attached to transaction A's body
    assert env.ledger.settle(QuorumRBC(body_a, (att_b["SV1"], att_b["SV2"]))).code == "DECISION_DIGEST_MISMATCH"
    # B's RBC body relabelled with A's tid: digest no longer matches signatures
    relabel = replace(body_b, values={**body_b.values, "settle_tid": a.spec.tid})
    assert env.ledger.settle(QuorumRBC(relabel, (att_b["SV1"], att_b["SV2"]))).code in {
        "WRONG_SESSION", "DECISION_DIGEST_MISMATCH"}


def test_replayed_rbc(env, acn_specs):
    s, body, att = _honest(env, acn_specs[11])
    rbc = QuorumRBC(body, (att["SV1"], att["SV2"]))
    assert env.ledger.settle(rbc).ok
    assert env.ledger.settle(rbc).code == "RBC_REPLAY"
    assert env.ledger.settle(QuorumRBC(body, (att["SV2"], att["SV3"]))).code == "RBC_REPLAY"


@pytest.mark.parametrize("behavior", ["inflate", "approve_all", "wrong_root"])
def test_one_malicious_two_honest_is_safe(acn_specs, behavior):
    env = DvasEnvironment(profile=PROFILES["C0"], behaviors={"SV2": behavior})
    s = ready(env, acn_specs[12], verify=True)
    rbc = s.aggregate()
    assert rbc is not None and {"SV1", "SV3"} <= {a.verifier_id for a in rbc.attestations}
    r = s.settle()
    assert r.ok and r.value["captured"] == s.spec.expected_amount
    mal = next(o for o in s.outcomes if o.verifier_id == "SV2")
    if mal.body is not None and mal.body.digest != rbc.body.digest:
        # malicious attestation alone, or mixed into the honest RBC, cannot settle
        assert env.ledger.settle(QuorumRBC(mal.body, (mal.attestation,))).code in {"BELOW_THRESHOLD", "RBC_REPLAY",
                                                                                  "RECEIPT_REPLAY"}


def test_malicious_verifier_alone_cannot_settle_invalid_delivery(acn_specs):
    """Over-cap delivery: two honest verifiers reject, one approve_all verifier cannot reach t=2."""
    env = DvasEnvironment(profile=PROFILES["C0"], behaviors={"SV2": "approve_all"})
    spec = replace(acn_specs[13], delivered_kwh=acn_specs[13].cap_kwh + Decimal("5"))
    s = ready(env, spec, verify=True)
    assert [o.ok for o in s.outcomes] == [False, True, False]
    assert s.aggregate() is None
    mal = s.outcomes[1]
    # rejected by SettleSC's public amount bound and/or the threshold, never accepted
    assert env.ledger.settle(QuorumRBC(mal.body, (mal.attestation,))).code in {"BELOW_THRESHOLD",
                                                                               "CAPTURE_EXCEEDS_LIMIT"}


def test_one_unavailable_verifier_still_settles(acn_specs):
    env = DvasEnvironment(profile=PROFILES["C0"], behaviors={"SV3": "offline"})
    r = env.run(acn_specs[14])
    assert r.ok and r.captured == acn_specs[14].expected_amount


def test_two_unavailable_verifiers_cannot_settle(acn_specs):
    env = DvasEnvironment(profile=PROFILES["C0"], behaviors={"SV2": "offline", "SV3": "offline"})
    r = env.run(acn_specs[15])
    assert not r.ok and r.stage == "quorum"


def test_threshold_assumption_two_colluding_verifiers(acn_specs):
    """Trust assumption: >= t colluding verifiers can settle an inflated
    amount, but SettleSC still bounds the capture by the user's hold."""
    env = DvasEnvironment(profile=PROFILES["C0"], behaviors={"SV1": "inflate", "SV2": "inflate"})
    s = ready(env, acn_specs[16], verify=True)
    rbc = s.aggregate()
    r = s.settle(rbc)
    assert r.ok and r.value["captured"] == env.ledger.records[s.spec.tid].captured
    assert r.value["captured"] <= s.spec.preauth_limit


def test_3_of_5_configuration(acn_specs):
    env = DvasEnvironment(profile=PROFILES["C0"], n=5, t=3, behaviors={"SV4": "offline", "SV5": "inflate"})
    r = env.run(acn_specs[17])
    assert r.ok and r.captured == acn_specs[17].expected_amount
    env2 = DvasEnvironment(profile=PROFILES["C0"], n=5, t=3, behaviors={"SV3": "offline", "SV4": "offline", "SV5": "offline"})
    assert not env2.run(acn_specs[18]).ok


def test_single_verifier_configuration(acn_specs):
    env = DvasEnvironment(profile=PROFILES["C0"], n=1, t=1)
    assert env.run(acn_specs[19]).ok


def test_minority_threshold_rejected_by_policy():
    with pytest.raises(ValueError):
        QuorumPolicy(3, 1)
    with pytest.raises(ValueError):
        QuorumPolicy(4, 2)
    assert QuorumPolicy(4, 2, allow_minority_threshold=True).t == 2


@pytest.mark.parametrize("field,value,code", [
    ("captured_amount", Decimal("1000000"), "CAPTURE_EXCEEDS_LIMIT"),
    ("captured_amount", Decimal("-1"), "CAPTURE_EXCEEDS_LIMIT"),
    ("refund_amount", Decimal("0"), "REFUND_MISMATCH"),
    ("dr_digest", "aa" * 32, "RECEIPT_DIGEST_MISMATCH"),
    ("settle_h_priv", "aa" * 32, "RECEIPT_DIGEST_MISMATCH"),
    ("auth_digest", "aa" * 32, "AUTH_STATE_CHANGED"),
    ("policy_id", "other-policy", "RBC_POLICY_MISMATCH"),
    ("decision", "REJECT", "RBC_NOT_ACCEPT"),
    ("rbc_version", "v0", "RBC_VERSION"),
    ("settle_meter_id", "M_OTHER", "WRONG_METER"),
])
def test_rbc_body_bounds_even_with_valid_quorum_signatures(env, acn_specs, field, value, code):
    """Even a full quorum of valid signatures cannot override SettleSC's public invariants."""
    s, body, att = _honest(env, acn_specs[20])
    bad = _resign_body(body, **{field: value})
    rbc = QuorumRBC(bad, (_att(env, "SV1", bad), _att(env, "SV2", bad), _att(env, "SV3", bad)))
    assert env.ledger.settle(rbc).code == code


def test_ml_dsa_attestation_profile(acn_specs):
    env = DvasEnvironment(profile=PROFILES["C4"])
    r = env.run(acn_specs[30])
    assert r.ok and r.captured == acn_specs[30].expected_amount
