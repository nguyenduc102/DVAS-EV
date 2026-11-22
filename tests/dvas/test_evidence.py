"""Section 7: single-ciphertext multi-recipient private evidence."""

from __future__ import annotations

from dataclasses import replace

import pytest

from dbas_et.dvas.evidence import (
    EvidenceContext,
    RecipientKey,
    WrappedKey,
    open_evidence,
    seal_evidence,
)
from dbas_et.dvas.profiles import MLKEM768, X25519, KEMKeypair, kem_encapsulate

CTX = EvidenceContext("tid-1", "sid-1", "11" * 32, "M_1", "22" * 32)


def _cluster(scheme, n=3):
    keys = {f"SV{i}": KEMKeypair(scheme) for i in range(1, n + 1)}
    rec = [RecipientKey(v, 1, scheme, k.public_key) for v, k in keys.items()]
    return keys, rec


@pytest.mark.parametrize("scheme", [X25519, MLKEM768])
def test_all_recipients_open_single_ciphertext(scheme):
    keys, rec = _cluster(scheme)
    env = seal_evidence(b"payload", CTX, rec)
    for v, k in keys.items():
        r = open_evidence(env, verifier_id=v, kem_epoch=1, kem_keypair=k, expected=CTX)
        assert r.ok and r.plaintext == b"payload"
    # payload encrypted once: ciphertext length independent of the number of recipients
    _, rec5 = _cluster(scheme, 5)
    assert len(seal_evidence(b"payload", CTX, rec5).ciphertext) == len(env.ciphertext)


@pytest.mark.parametrize("scheme", [X25519, MLKEM768])
def test_wrong_verifier_cannot_decrypt(scheme):
    keys, rec = _cluster(scheme)
    env = seal_evidence(b"p", CTX, rec[:2])  # SV3 not a recipient
    assert open_evidence(env, verifier_id="SV3", kem_epoch=1, kem_keypair=keys["SV3"], expected=CTX).reason == "NOT_A_RECIPIENT"
    # SV3 trying SV1's slot with its own secret key
    assert open_evidence(env, verifier_id="SV1", kem_epoch=1, kem_keypair=keys["SV3"], expected=CTX).reason in {
        "KEY_UNWRAP_FAILED", "KEM_FAILED:Exception", "KEM_FAILED:ValueError"} or \
        not open_evidence(env, verifier_id="SV1", kem_epoch=1, kem_keypair=keys["SV3"], expected=CTX).ok


@pytest.mark.parametrize("field,value", [("tid", "tid-2"), ("sid", "sid-2"), ("rho_t", "33" * 32),
                                         ("meter_id", "M_2"), ("h_priv", "44" * 32)])
def test_context_binding(field, value):
    keys, rec = _cluster(X25519)
    env = seal_evidence(b"p", CTX, rec)
    other = replace(CTX, **{field: value})
    assert open_evidence(env, verifier_id="SV1", kem_epoch=1, kem_keypair=keys["SV1"], expected=other).reason == "CONTEXT_MISMATCH"
    # relabelling the envelope context to match the expected one breaks AEAD
    moved = replace(env, context=other)
    r = open_evidence(moved, verifier_id="SV1", kem_epoch=1, kem_keypair=keys["SV1"], expected=other)
    assert not r.ok and r.reason in {"KEY_UNWRAP_FAILED", "PAYLOAD_AEAD_FAILED"}


def test_ciphertext_tampering():
    keys, rec = _cluster(MLKEM768)
    env = seal_evidence(b"payload", CTX, rec)
    ct = bytearray(env.ciphertext); ct[0] ^= 1
    r = open_evidence(replace(env, ciphertext=bytes(ct)), verifier_id="SV1", kem_epoch=1, kem_keypair=keys["SV1"], expected=CTX)
    assert r.reason == "PAYLOAD_AEAD_FAILED"


def test_substituted_wrapped_key():
    """Attacker wraps its own content key for SV1 (valid KEM ct) without re-encrypting the payload."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    from dbas_et.dvas import evidence as ev

    keys, rec = _cluster(MLKEM768)
    env = seal_evidence(b"payload", CTX, rec)
    kem_ct, ss = kem_encapsulate(MLKEM768, rec[0].public_key)
    ctx_digest = CTX.digest(env.recipients_digest())
    kek = ev._kek(ss, ctx_digest, rec[0], kem_ct, rec[0].pkid)
    k2 = ChaCha20Poly1305.generate_key()
    w = WrappedKey("SV1", 1, MLKEM768, kem_ct, b"\x00" * 12,
                   ChaCha20Poly1305(kek).encrypt(b"\x00" * 12, k2, ctx_digest + b"SV1"))
    env2 = replace(env, recipients=(w,) + env.recipients[1:])
    r = open_evidence(env2, verifier_id="SV1", kem_epoch=1, kem_keypair=keys["SV1"], expected=CTX)
    assert r.reason == "PAYLOAD_AEAD_FAILED"


def test_revoked_verifier_excluded_for_new_transactions(env, acn_specs):
    from ..conftest import ready

    env.registry.revoke("SV3")
    assert [r.verifier_id for r in env.recipients()] == ["SV1", "SV2"]
    s = ready(env, acn_specs[20], verify=True)
    by = {o.verifier_id: o for o in s.outcomes}
    assert by["SV3"].reason == "PRIVATE_NOT_A_RECIPIENT"
    assert by["SV1"].ok and by["SV2"].ok
    assert s.aggregate() is not None and s.settle().ok  # 2-of-3 still settles


def test_kem_epoch_mismatch():
    keys, rec = _cluster(X25519)
    env = seal_evidence(b"p", CTX, rec)
    assert open_evidence(env, verifier_id="SV1", kem_epoch=2, kem_keypair=keys["SV1"], expected=CTX).reason == "KEM_EPOCH_OR_SCHEME_MISMATCH"
