"""
Multi-recipient private delivery evidence.

DR_private is encrypted once under a fresh random content key K_t with
ChaCha20-Poly1305.  K_t is then wrapped independently for every authorised
verifier using that verifier's registered KEM key (ML-KEM-768 or X25519,
per profile):

    (ct_i, ss_i)  = KEM.Encap(pk_i)
    kek_i         = HKDF-SHA256(ss_i, salt = H(ctx), info = "DVAS-EV/kek/v1" | verifier_id | epoch | ct_i | pkid_i)
    wrapped_i     = ChaCha20-Poly1305(kek_i).Enc(n_i, K_t, aad = ctx_digest | verifier_id)

ctx = (protocol, tid, sid, rho_t, meter_id, h_priv, recipients digest).  The
payload AEAD uses ctx as associated data, so a ciphertext moved to another
transaction/session/root fails authentication.

This layer does not authenticate the sender.  Anyone holding the
verifiers' public KEM keys can produce a valid envelope.  Authenticity of
the payload comes from comparing H(DR_private) with the ``h_priv`` signed by
the registered meter in the public receipt (see ``delivery`` and
``verifier``).
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from typing import Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .canonical import tagged_hash
from .instrumentation import count
from .profiles import KEMKeypair, kem_encapsulate

ENVELOPE_VERSION = "dvas-ev-evidence-v1"
AEAD_ALG = "ChaCha20-Poly1305"


@dataclass(frozen=True)
class RecipientKey:
    verifier_id: str
    kem_epoch: int
    kem_scheme: str
    public_key: bytes

    @property
    def pkid(self) -> bytes:
        return tagged_hash("DVAS-EV/kem-pkid/v1", self.kem_scheme.encode(), self.public_key)


@dataclass(frozen=True)
class WrappedKey:
    verifier_id: str
    kem_epoch: int
    kem_scheme: str
    kem_ct: bytes
    nonce: bytes
    wrapped: bytes


@dataclass(frozen=True)
class EvidenceContext:
    tid: str
    sid: str
    rho_t: str
    meter_id: str
    h_priv: str

    def digest(self, recipients_digest: bytes) -> bytes:
        return tagged_hash(
            "DVAS-EV/evidence-ctx/v1",
            ENVELOPE_VERSION.encode(), self.tid.encode(), self.sid.encode(), bytes.fromhex(self.rho_t),
            self.meter_id.encode(), bytes.fromhex(self.h_priv), recipients_digest,
        )


@dataclass(frozen=True)
class EvidenceEnvelope:
    version: str
    context: EvidenceContext
    nonce: bytes
    ciphertext: bytes
    recipients: tuple[WrappedKey, ...] = field(default_factory=tuple)

    def recipients_digest(self) -> bytes:
        return _recipients_digest([(w.verifier_id, w.kem_epoch, w.kem_scheme) for w in self.recipients])

    def size_bytes(self) -> int:
        n = len(self.nonce) + len(self.ciphertext)
        for w in self.recipients:
            n += len(w.verifier_id) + 2 + len(w.kem_ct) + len(w.nonce) + len(w.wrapped)
        return n


def _recipients_digest(items: Sequence[tuple[str, int, str]]) -> bytes:
    parts = [f"{v}|{e}|{s}".encode() for v, e, s in sorted(items)]
    return tagged_hash("DVAS-EV/evidence-recipients/v1", *parts)


def _kek(ss: bytes, ctx_digest: bytes, r: RecipientKey | WrappedKey, kem_ct: bytes, pkid: bytes) -> bytes:
    info = b"DVAS-EV/kek/v1|" + r.verifier_id.encode() + b"|" + struct.pack(">I", r.kem_epoch) + b"|" + kem_ct + b"|" + pkid
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=ctx_digest, info=info).derive(ss)


def seal_evidence(plaintext: bytes, ctx: EvidenceContext, recipients: Sequence[RecipientKey]) -> EvidenceEnvelope:
    if not recipients:
        raise ValueError("at least one verifier recipient is required")
    rdig = _recipients_digest([(r.verifier_id, r.kem_epoch, r.kem_scheme) for r in recipients])
    ctx_digest = ctx.digest(rdig)
    content_key = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)
    count("aead_enc")
    ciphertext = ChaCha20Poly1305(content_key).encrypt(nonce, plaintext, ctx_digest)
    wrapped: list[WrappedKey] = []
    for r in sorted(recipients, key=lambda x: x.verifier_id):
        kem_ct, ss = kem_encapsulate(r.kem_scheme, r.public_key)
        kek = _kek(ss, ctx_digest, r, kem_ct, r.pkid)
        wn = os.urandom(12)
        count("aead_enc")
        w = ChaCha20Poly1305(kek).encrypt(wn, content_key, ctx_digest + r.verifier_id.encode())
        wrapped.append(WrappedKey(r.verifier_id, r.kem_epoch, r.kem_scheme, kem_ct, wn, w))
    return EvidenceEnvelope(ENVELOPE_VERSION, ctx, nonce, ciphertext, tuple(wrapped))


@dataclass(frozen=True)
class OpenResult:
    ok: bool
    reason: str
    plaintext: bytes | None = None


def open_evidence(
    env: EvidenceEnvelope,
    *,
    verifier_id: str,
    kem_epoch: int,
    kem_keypair: KEMKeypair,
    expected: EvidenceContext,
) -> OpenResult:
    """Open the envelope as ``verifier_id``.  ``expected`` comes from the
    meter-signed public receipt and the ledger, never from the envelope."""
    if env.version != ENVELOPE_VERSION:
        return OpenResult(False, "ENVELOPE_VERSION")
    if env.context != expected:
        return OpenResult(False, "CONTEXT_MISMATCH")
    slot = [w for w in env.recipients if w.verifier_id == verifier_id]
    if not slot:
        return OpenResult(False, "NOT_A_RECIPIENT")
    w = slot[0]
    if w.kem_epoch != kem_epoch or w.kem_scheme != kem_keypair.scheme:
        return OpenResult(False, "KEM_EPOCH_OR_SCHEME_MISMATCH")
    ctx_digest = expected.digest(env.recipients_digest())
    try:
        ss = kem_keypair.decapsulate(w.kem_ct)
        pkid = RecipientKey(verifier_id, kem_epoch, kem_keypair.scheme, kem_keypair.public_key).pkid
        kek = _kek(ss, ctx_digest, w, w.kem_ct, pkid)
        count("aead_dec")
        content_key = ChaCha20Poly1305(kek).decrypt(w.nonce, w.wrapped, ctx_digest + verifier_id.encode())
    except InvalidTag:
        return OpenResult(False, "KEY_UNWRAP_FAILED")
    except Exception as exc:  # e.g. malformed KEM ciphertext
        return OpenResult(False, f"KEM_FAILED:{type(exc).__name__}")
    try:
        count("aead_dec")
        pt = ChaCha20Poly1305(content_key).decrypt(env.nonce, env.ciphertext, ctx_digest)
    except InvalidTag:
        return OpenResult(False, "PAYLOAD_AEAD_FAILED")
    return OpenResult(True, "OK", pt)
