"""Registry and key lifecycle."""

from __future__ import annotations

import pytest

from dbas_et.dvas.profiles import ECDSA, Signer
from dbas_et.dvas.registry import KeyRegistry, KeyStatus, Role

from ..conftest import ready


def _k():
    return Signer(ECDSA).public_key


def test_register_activate_rotate_revoke_lookup():
    reg = KeyRegistry()
    r = reg.register("M1", Role.METER, "OP_A", _k(), ECDSA, activate=False)
    assert r.status == KeyStatus.REGISTERED and reg.lookup("M1", Role.METER).reason == "NOT_ACTIVE"
    reg.activate("M1")
    assert reg.lookup("M1", Role.METER).ok and reg.role_of("M1") == Role.METER
    r2 = reg.rotate("M1", _k(), ECDSA)
    assert r2.key_epoch == 2
    assert reg.lookup("M1", Role.METER, epoch=1).reason == "STALE_EPOCH"
    assert reg.lookup("M1", Role.METER, epoch=2).ok
    assert reg.lookup("M1", Role.METER, epoch=9).reason == "UNKNOWN_EPOCH"
    reg.revoke("M1")
    assert reg.lookup("M1", Role.METER).reason == "REVOKED"
    with pytest.raises(ValueError):
        reg.rotate("M1", _k(), ECDSA)
    with pytest.raises(ValueError):
        reg.register("M1", Role.METER, "OP_A", _k(), ECDSA)


def test_wrong_role_and_unregistered():
    reg = KeyRegistry()
    reg.register("SV1", Role.VERIFIER, "V", _k(), ECDSA)
    assert reg.lookup("SV1", Role.METER).reason == "WRONG_ROLE"
    assert reg.lookup("nobody", Role.VERIFIER).reason == "UNREGISTERED"
    with pytest.raises(ValueError):
        reg.register("SV1", Role.METER, "V", _k(), ECDSA)
    with pytest.raises(ValueError):
        reg.register("SV1", Role.VERIFIER, "V", _k(), ECDSA)  # second active key without rotate


def test_validity_interval():
    reg = KeyRegistry()
    reg.register("U", Role.USER, "OH", _k(), ECDSA, valid_from=100, valid_until=200)
    assert reg.lookup("U", Role.USER, at=150).ok
    assert reg.lookup("U", Role.USER, at=250).reason == "EXPIRED"


def test_verifier_set_epoch_changes_on_membership_change():
    reg = KeyRegistry()
    reg.register("SV1", Role.VERIFIER, "V", _k(), ECDSA)
    e1 = reg.verifier_set_epoch
    reg.register("SV2", Role.VERIFIER, "V", _k(), ECDSA)
    reg.revoke("SV1")
    assert reg.verifier_set_epoch > e1
    assert [r.entity_id for r in reg.active_verifiers()] == ["SV2"]


def test_bind_meter_requires_registered_roles():
    reg = KeyRegistry()
    reg.register("M1", Role.METER, "OP", _k(), ECDSA)
    with pytest.raises(ValueError):
        reg.bind_meter("M1", "S_missing")


def test_invalid_station_meter_binding_rejected(env, acn_specs):
    """Meter registered to another station cannot authorize or deliver for this station."""
    spec = acn_specs[21]
    s = env.session(spec)
    other = next(x for x in acn_specs if x.station_id != spec.station_id)
    env.register_spec(other)
    env.registry.meter_station[spec.meter_id] = other.station_id  # RA binds the meter elsewhere
    s.commit()
    r = s.authorize()
    assert not r.ok and "registry_meter_station" in r.detail


def test_revoked_user_and_station(env, acn_specs):
    s = env.session(acn_specs[22])
    s.commit()
    env.registry.revoke(s.spec.user_id)
    assert s.authorize().code == "USER_KEY_REVOKED"
    s2 = env.session(acn_specs[23])
    s2.commit(); assert s2.authorize().ok
    env.registry.revoke(s2.spec.station_id)
    assert s2.open_session().code == "STATION_KEY_REVOKED"


def test_unregistered_signer_for_authorization(env, acn_specs):
    s = env.session(acn_specs[24])
    s.commit()
    assert s.authorize(signer=Signer(env.profile.auth_sig)).code == "BAD_USER_SIGNATURE"


def test_revoked_verifier_attestation_rejected(env, acn_specs):
    s = ready(env, acn_specs[25], verify=False)
    env.registry.revoke("SV3")  # before verification: new verifier-set epoch
    s.verify()
    # SV3 still holds its signing key and signs a mathematically valid attestation
    sv3 = env.verifiers["SV3"]
    from dbas_et.dvas.rbc import QuorumRBC, VerificationAttestation, attestation_message

    body = s.outcomes[0].body
    sig = sv3.signer.sign(attestation_message("SV3", sv3.key_epoch, body.digest))
    att3 = VerificationAttestation.for_body(body, "SV3", sv3.key_epoch, sig, sv3.signer.scheme)
    rbc = QuorumRBC(body, (s.outcomes[0].attestation, att3))
    assert env.ledger.settle(rbc).code == "VERIFIER_KEY_REVOKED"
