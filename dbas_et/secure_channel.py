from __future__ import annotations

import dataclasses
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, asdict
from typing import Any, Literal, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from dbas_et.crypto import (
    OQS_AVAILABLE,
    PQKEMKeypair,
    gen_pq_kem_keypair,
    oqs,
    require_oqs_kem_algorithm,
)

AEADAlgorithm = Literal["ChaCha20-Poly1305", "AES-GCM"]
KEMBackend = Literal["oqs", "mock-sha256", "auto"]


def canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def sha256_hex(label: str, payload: Any) -> str:
    h = hashlib.sha256()
    h.update(label.encode("utf-8"))
    h.update(b"\x00")
    if isinstance(payload, bytes):
        h.update(payload)
    else:
        h.update(canonical_json(payload))
    return h.hexdigest()


@dataclass(frozen=True)
class KEMAEADEnvelope:
    version: str
    kem_backend: str
    kem_algorithm: str
    aead_algorithm: str
    recipient_pkid: str
    kem_ciphertext_hex: str
    nonce_hex: str
    ciphertext_hex: str
    aad_digest: str
    plaintext_digest: str
    plaintext_len: int
    warning: str = ""


@dataclass(frozen=True)
class KEMAEADOpenResult:
    ok: bool
    reason: str
    payload: dict[str, Any] | None
    plaintext_len: int
    aad_digest: str


def _derive_aead_key(
    *,
    shared_secret: bytes,
    kem_algorithm: str,
    aead_algorithm: str,
    recipient_pkid: str,
    context: Mapping[str, Any],
) -> bytes:
    """
    Derive a 256-bit AEAD key from the KEM shared secret.

    The salt binds the transaction and session. The info field binds protocol
    role, phase, payload type, recipient and algorithms.
    """
    ctx = dict(context)

    salt_material = {
        "protocol": "DBAS-ET-KEM-AEAD-v2",
        "trade_id": ctx.get("trade_id", ""),
        "rho_t": ctx.get("rho_t", ""),
        "sid_t": ctx.get("sid_t", ""),
    }

    info_material = {
        "protocol": "DBAS-ET-KEM-AEAD-v2",
        "phase": ctx.get("phase", ""),
        "payload_type": ctx.get("payload_type", ""),
        "sender_id": ctx.get("sender_id", ""),
        "recipient_id": ctx.get("recipient_id", ""),
        "recipient_role": ctx.get("recipient_role", ""),
        "recipient_pkid": recipient_pkid,
        "kem_algorithm": kem_algorithm,
        "aead_algorithm": aead_algorithm,
        "policy_version": ctx.get("policy_version", ""),
    }

    salt = hashlib.sha256(canonical_json(salt_material)).digest()
    info = canonical_json(info_material)

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(shared_secret)


def _aad(
    *,
    kem_algorithm: str,
    aead_algorithm: str,
    recipient_pkid: str,
    context: Mapping[str, Any],
) -> bytes:
    return canonical_json(
        {
            "protocol": "DBAS-ET-KEM-AEAD-v2",
            "kem_algorithm": kem_algorithm,
            "aead_algorithm": aead_algorithm,
            "recipient_pkid": recipient_pkid,
            "context": dict(context),
        }
    )


def _encrypt_aead(aead_algorithm: str, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    if aead_algorithm == "ChaCha20-Poly1305":
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)

    if aead_algorithm == "AES-GCM":
        return AESGCM(key).encrypt(nonce, plaintext, aad)

    raise ValueError(f"unsupported AEAD algorithm: {aead_algorithm}")


def _decrypt_aead(aead_algorithm: str, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    if aead_algorithm == "ChaCha20-Poly1305":
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)

    if aead_algorithm == "AES-GCM":
        return AESGCM(key).decrypt(nonce, ciphertext, aad)

    raise ValueError(f"unsupported AEAD algorithm: {aead_algorithm}")


def _encapsulate_to_public(
    *,
    recipient_pk: bytes,
    recipient_pkid: str,
    kem_algorithm: str,
    kem_backend: str,
) -> tuple[bytes, bytes, str, str]:
    """
    Return kem_ciphertext, shared_secret, actual_backend, warning.

    mock-sha256 is deterministic plumbing for portable artifact execution.
    It is not cryptographically secure and is not used in any reported result.
    """
    if kem_backend in {"oqs", "auto"}:
        try:
            require_oqs_kem_algorithm(kem_algorithm)
            with oqs.KeyEncapsulation(kem_algorithm) as kem:
                kem_ct, ss = kem.encap_secret(recipient_pk)
            return bytes(kem_ct), bytes(ss), "oqs", ""
        except Exception:
            if kem_backend == "oqs":
                raise

    # Portable fallback for tests only.
    nonce = secrets.token_bytes(32)
    kem_ct = nonce
    ss = hashlib.sha256(
        b"DBAS-ET-MOCK-KEM-SS-v1|" + recipient_pk + b"|" + recipient_pkid.encode("utf-8") + b"|" + nonce
    ).digest()
    return kem_ct, ss, "mock-sha256", "not_pq_secure_mock_kem"


def _decapsulate_with_keypair(
    *,
    recipient_kem_keypair: PQKEMKeypair,
    kem_ciphertext: bytes,
    kem_backend: str,
    kem_algorithm: str,
) -> bytes:
    if kem_backend == "oqs":
        require_oqs_kem_algorithm(kem_algorithm)
        return recipient_kem_keypair.decapsulate(kem_ciphertext)

    if kem_backend == "mock-sha256":
        return hashlib.sha256(
            b"DBAS-ET-MOCK-KEM-SS-v1|"
            + recipient_kem_keypair.pk
            + b"|"
            + recipient_kem_keypair.pkid.encode("utf-8")
            + b"|"
            + kem_ciphertext
        ).digest()

    raise ValueError(f"unsupported KEM backend in envelope: {kem_backend}")


def seal_json_to_recipient(
    *,
    payload: Mapping[str, Any],
    recipient_kem_pk: bytes,
    recipient_pkid: str,
    context: Mapping[str, Any],
    kem_algorithm: str = "ML-KEM-768",
    kem_backend: KEMBackend = "auto",
    aead_algorithm: AEADAlgorithm = "ChaCha20-Poly1305",
) -> KEMAEADEnvelope:
    plaintext = canonical_json(dict(payload))

    kem_ct, ss, actual_backend, warning = _encapsulate_to_public(
        recipient_pk=recipient_kem_pk,
        recipient_pkid=recipient_pkid,
        kem_algorithm=kem_algorithm,
        kem_backend=kem_backend,
    )

    aad = _aad(
        kem_algorithm=kem_algorithm,
        aead_algorithm=aead_algorithm,
        recipient_pkid=recipient_pkid,
        context=context,
    )

    key = _derive_aead_key(
        shared_secret=ss,
        kem_algorithm=kem_algorithm,
        aead_algorithm=aead_algorithm,
        recipient_pkid=recipient_pkid,
        context=context,
    )

    nonce = secrets.token_bytes(12)
    ciphertext = _encrypt_aead(aead_algorithm, key, nonce, plaintext, aad)

    return KEMAEADEnvelope(
        version="DBAS-ET-KEM-AEAD-v2",
        kem_backend=actual_backend,
        kem_algorithm=kem_algorithm,
        aead_algorithm=aead_algorithm,
        recipient_pkid=recipient_pkid,
        kem_ciphertext_hex=kem_ct.hex(),
        nonce_hex=nonce.hex(),
        ciphertext_hex=ciphertext.hex(),
        aad_digest=sha256_hex("DBAS-ET:KEM-AEAD:AAD:v2", aad),
        plaintext_digest=sha256_hex("DBAS-ET:KEM-AEAD:PLAINTEXT:v2", plaintext),
        plaintext_len=len(plaintext),
        warning=warning,
    )


def open_json_from_envelope(
    *,
    envelope: KEMAEADEnvelope | Mapping[str, Any],
    recipient_kem_keypair: PQKEMKeypair,
    context: Mapping[str, Any],
) -> KEMAEADOpenResult:
    if not dataclasses.is_dataclass(envelope):
        env = KEMAEADEnvelope(**dict(envelope))
    else:
        env = envelope

    aad = _aad(
        kem_algorithm=env.kem_algorithm,
        aead_algorithm=env.aead_algorithm,
        recipient_pkid=env.recipient_pkid,
        context=context,
    )
    aad_digest = sha256_hex("DBAS-ET:KEM-AEAD:AAD:v2", aad)

    if aad_digest != env.aad_digest:
        return KEMAEADOpenResult(
            ok=False,
            reason="AAD_DIGEST_MISMATCH",
            payload=None,
            plaintext_len=0,
            aad_digest=aad_digest,
        )

    try:
        ss = _decapsulate_with_keypair(
            recipient_kem_keypair=recipient_kem_keypair,
            kem_ciphertext=bytes.fromhex(env.kem_ciphertext_hex),
            kem_backend=env.kem_backend,
            kem_algorithm=env.kem_algorithm,
        )

        key = _derive_aead_key(
            shared_secret=ss,
            kem_algorithm=env.kem_algorithm,
            aead_algorithm=env.aead_algorithm,
            recipient_pkid=env.recipient_pkid,
            context=context,
        )

        plaintext = _decrypt_aead(
            env.aead_algorithm,
            key,
            bytes.fromhex(env.nonce_hex),
            bytes.fromhex(env.ciphertext_hex),
            aad,
        )

        if sha256_hex("DBAS-ET:KEM-AEAD:PLAINTEXT:v2", plaintext) != env.plaintext_digest:
            return KEMAEADOpenResult(
                ok=False,
                reason="PLAINTEXT_DIGEST_MISMATCH",
                payload=None,
                plaintext_len=0,
                aad_digest=aad_digest,
            )

        payload = json.loads(plaintext.decode("utf-8"))
        return KEMAEADOpenResult(
            ok=True,
            reason="OK",
            payload=payload,
            plaintext_len=len(plaintext),
            aad_digest=aad_digest,
        )

    except InvalidTag:
        return KEMAEADOpenResult(
            ok=False,
            reason="AEAD_AUTHENTICATION_FAILED",
            payload=None,
            plaintext_len=0,
            aad_digest=aad_digest,
        )
    except Exception as exc:
        return KEMAEADOpenResult(
            ok=False,
            reason=f"OPEN_FAILED:{type(exc).__name__}",
            payload=None,
            plaintext_len=0,
            aad_digest=aad_digest,
        )


def envelope_to_dict(env: KEMAEADEnvelope) -> dict[str, Any]:
    return asdict(env)


def open_result_to_dict(result: KEMAEADOpenResult) -> dict[str, Any]:
    return asdict(result)


def generate_kem_recipient(
    *,
    kem_algorithm: str = "ML-KEM-768",
    kem_backend: KEMBackend = "auto",
    strict_pq: bool = False,
) -> PQKEMKeypair:
    return gen_pq_kem_keypair(
        algorithm=kem_algorithm,
        backend=kem_backend,
        strict=strict_pq,
    )
