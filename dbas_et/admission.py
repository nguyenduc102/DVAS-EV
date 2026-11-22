"""
Admission certificate utilities for DBAS-ET.

This module connects the off-chain validator decision with AuthSC.  It is a
simulation artifact: validators sign a compact admission certificate over
(trade_id, rho_t, A_t digest, policy digest).  AuthSC can then verify the
certificate before reserving funds.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any, Mapping

from .crypto import H, H_hex, ecdsa_sign, ecdsa_verify
from .entities import ValidatorNode
from .projections import ProjectionView


def admission_view_digest(A_view: ProjectionView | Mapping[str, Any]) -> str:
    """Digest the admission projection view with domain separation."""
    if hasattr(A_view, "to_record"):
        record = A_view.to_record()  # type: ignore[attr-defined]
    else:
        record = dict(A_view)
    return H_hex("DBAS-ET:ADMISSION-VIEW:v1", record)


@dataclass(frozen=True)
class AdmissionCertificate:
    """
    Validator-signed admission certificate.

    The certificate proves that an entry validator accepted the admission
    projection before AuthSC reserves funds.  It intentionally signs a compact
    digest rather than the full capsule.
    """

    validator_id: str
    trade_id: str
    rho_t: str
    admission_view_digest: str
    policy_digest: str
    issued_at: float
    signature_hex: str
    cert_version: str = "admission-cert-v1"

    def unsigned_record(self) -> dict[str, Any]:
        return {
            "cert_version": self.cert_version,
            "validator_id": self.validator_id,
            "trade_id": self.trade_id,
            "rho_t": self.rho_t,
            "admission_view_digest": self.admission_view_digest,
            "policy_digest": self.policy_digest,
            "issued_at": self.issued_at,
        }

    def to_record(self) -> dict[str, Any]:
        return asdict(self)


def build_admission_message(cert_unsigned_record: Mapping[str, Any]) -> bytes:
    """Canonical message signed by the validator."""
    return H("DBAS-ET:ADMISSION-CERT-TO-SIGN:v1", dict(cert_unsigned_record))


def issue_admission_certificate(
    *,
    validator: ValidatorNode,
    trade_id: str,
    rho_t: str,
    A_view: ProjectionView,
    policy_record: Mapping[str, Any] | None = None,
    issued_at: float | None = None,
) -> AdmissionCertificate:
    """Issue a validator-signed admission certificate."""
    unsigned = {
        "cert_version": "admission-cert-v1",
        "validator_id": validator.validator_id,
        "trade_id": str(trade_id),
        "rho_t": str(rho_t),
        "admission_view_digest": admission_view_digest(A_view),
        "policy_digest": H_hex("DBAS-ET:ADMISSION-POLICY:v1", dict(policy_record or {})),
        "issued_at": float(time.time() if issued_at is None else issued_at),
    }
    sig = ecdsa_sign(validator.sign_sk, build_admission_message(unsigned))
    return AdmissionCertificate(signature_hex=sig.hex(), **unsigned)


def verify_admission_certificate(
    *,
    validator: ValidatorNode,
    certificate: AdmissionCertificate | Mapping[str, Any],
    trade_id: str,
    rho_t: str,
    A_view: ProjectionView,
    policy_record: Mapping[str, Any] | None = None,
) -> bool:
    """Verify a validator admission certificate against current context."""
    cert = certificate if isinstance(certificate, AdmissionCertificate) else AdmissionCertificate(**dict(certificate))

    if cert.validator_id != validator.validator_id:
        return False
    if cert.trade_id != str(trade_id):
        return False
    if cert.rho_t != str(rho_t):
        return False
    if cert.admission_view_digest != admission_view_digest(A_view):
        return False

    expected_policy_digest = H_hex("DBAS-ET:ADMISSION-POLICY:v1", dict(policy_record or {}))
    if cert.policy_digest != expected_policy_digest:
        return False

    return ecdsa_verify(
        validator.sign_pk,
        build_admission_message(cert.unsigned_record()),
        bytes.fromhex(cert.signature_hex),
    )
