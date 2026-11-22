from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass, asdict
from typing import Any, Mapping

from dbas_et.crypto import PQKEMKeypair
from dbas_et.secure_channel import (
    generate_kem_recipient,
    open_json_from_envelope,
    seal_json_to_recipient,
    envelope_to_dict,
)

PRIVATE_PAYLOAD_TYPES = {
    "AuthRecordPrivate",
    "DeliveryReceiptPrivate",
    "ReceiptBindingPrivate",
    "MeterValuesPrivate",
    "SettlementPrivate",
}


def canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def digest_hex(label: str, payload: Any) -> str:
    h = hashlib.sha256()
    h.update(label.encode("utf-8"))
    h.update(b"\x00")
    if isinstance(payload, bytes):
        h.update(payload)
    else:
        h.update(canonical_json(payload))
    return h.hexdigest()


def make_protection_context(
    *,
    payload_type: str,
    phase: str,
    trade_id: str,
    recipient_role: str,
    rho_t: str = "",
    sid_t: str = "",
    sender_id: str = "",
    recipient_id: str = "",
    recipient_kem_pkid: str = "",
    policy_version: str = "protected-flow-v2",
) -> dict[str, Any]:
    if payload_type not in PRIVATE_PAYLOAD_TYPES:
        raise ValueError(f"unsupported private payload type: {payload_type}")

    return {
        "protocol": "DBAS-ET",
        "policy_version": policy_version,
        "payload_type": payload_type,
        "phase": phase,
        "trade_id": str(trade_id),
        "rho_t": str(rho_t),
        "sid_t": str(sid_t),
        "sender_id": str(sender_id),
        "recipient_id": str(recipient_id),
        "recipient_role": str(recipient_role),
        "recipient_kem_pkid": str(recipient_kem_pkid),
        "purpose": "mandatory_private_payload_protection",
    }


@dataclass(frozen=True)
class ProtectedProtocolPayload:
    payload_type: str
    phase: str
    trade_id: str
    recipient_role: str
    rho_t: str
    plaintext_digest: str
    envelope: dict[str, Any]
    protection_context_digest: str

    # Backward-compatible optional context fields.
    policy_version: str = "protected-flow-v2"
    sid_t: str = ""
    sender_id: str = ""
    recipient_id: str = ""
    recipient_kem_pkid: str = ""


@dataclass(frozen=True)
class ProtectedOpenResult:
    ok: bool
    reason: str
    payload_type: str
    phase: str
    trade_id: str
    recipient_role: str
    sid_t: str
    sender_id: str
    recipient_id: str
    recipient_kem_pkid: str
    plaintext_digest_expected: str
    plaintext_digest_opened: str
    payload: dict[str, Any] | None


def protect_protocol_payload(
    *,
    payload_type: str,
    phase: str,
    trade_id: str,
    payload: Mapping[str, Any],
    recipient_kem_pk: bytes,
    recipient_pkid: str,
    recipient_role: str,
    rho_t: str = "",
    sid_t: str = "",
    sender_id: str = "",
    recipient_id: str = "",
    kem_backend: str = "oqs",
    kem_algorithm: str = "ML-KEM-768",
    aead_algorithm: str = "ChaCha20-Poly1305",
) -> ProtectedProtocolPayload:
    recipient_id = recipient_id or recipient_role

    context = make_protection_context(
        payload_type=payload_type,
        phase=phase,
        trade_id=trade_id,
        recipient_role=recipient_role,
        rho_t=rho_t,
        sid_t=sid_t,
        sender_id=sender_id,
        recipient_id=recipient_id,
        recipient_kem_pkid=recipient_pkid,
    )

    env = seal_json_to_recipient(
        payload=dict(payload),
        recipient_kem_pk=recipient_kem_pk,
        recipient_pkid=recipient_pkid,
        context=context,
        kem_backend=kem_backend,
        kem_algorithm=kem_algorithm,
        aead_algorithm=aead_algorithm,
    )

    return ProtectedProtocolPayload(
        payload_type=payload_type,
        phase=phase,
        trade_id=str(trade_id),
        recipient_role=recipient_role,
        rho_t=str(rho_t),
        sid_t=str(sid_t),
        sender_id=str(sender_id),
        recipient_id=str(recipient_id),
        recipient_kem_pkid=str(recipient_pkid),
        plaintext_digest=digest_hex("DBAS-ET:protected-payload:v2", dict(payload)),
        envelope=envelope_to_dict(env),
        protection_context_digest=digest_hex("DBAS-ET:protected-context:v2", context),
    )


def open_protocol_payload(
    *,
    protected_payload: ProtectedProtocolPayload | Mapping[str, Any],
    recipient_kem_keypair: PQKEMKeypair,
) -> ProtectedOpenResult:
    if dataclasses.is_dataclass(protected_payload):
        pp = protected_payload
    else:
        raw = dict(protected_payload)
        # Allow older v1 records to open with default missing fields.
        pp = ProtectedProtocolPayload(**raw)

    context = make_protection_context(
        payload_type=pp.payload_type,
        phase=pp.phase,
        trade_id=pp.trade_id,
        recipient_role=pp.recipient_role,
        rho_t=pp.rho_t,
        sid_t=pp.sid_t,
        sender_id=pp.sender_id,
        recipient_id=pp.recipient_id,
        recipient_kem_pkid=pp.recipient_kem_pkid,
        policy_version=pp.policy_version,
    )

    opened = open_json_from_envelope(
        envelope=pp.envelope,
        recipient_kem_keypair=recipient_kem_keypair,
        context=context,
    )

    opened_digest = ""
    if opened.ok and opened.payload is not None:
        opened_digest = digest_hex("DBAS-ET:protected-payload:v2", opened.payload)

    digest_ok = bool(opened.ok and opened_digest == pp.plaintext_digest)

    return ProtectedOpenResult(
        ok=digest_ok,
        reason="OK" if digest_ok else opened.reason,
        payload_type=pp.payload_type,
        phase=pp.phase,
        trade_id=pp.trade_id,
        recipient_role=pp.recipient_role,
        sid_t=pp.sid_t,
        sender_id=pp.sender_id,
        recipient_id=pp.recipient_id,
        recipient_kem_pkid=pp.recipient_kem_pkid,
        plaintext_digest_expected=pp.plaintext_digest,
        plaintext_digest_opened=opened_digest,
        payload=opened.payload if digest_ok else None,
    )


def protected_payload_to_dict(pp: ProtectedProtocolPayload) -> dict[str, Any]:
    return asdict(pp)


def protected_open_result_to_dict(result: ProtectedOpenResult) -> dict[str, Any]:
    return asdict(result)


def generate_protected_flow_recipient(
    *,
    kem_algorithm: str = "ML-KEM-768",
    kem_backend: str = "oqs",
    strict_pq: bool = True,
) -> PQKEMKeypair:
    return generate_kem_recipient(
        kem_algorithm=kem_algorithm,
        kem_backend=kem_backend,
        strict_pq=strict_pq,
    )
