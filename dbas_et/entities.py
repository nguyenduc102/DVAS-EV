"""
Entity definitions for DBAS-ET.

The schema follows the paper model:

- User U_i
- Charging Station S_j
- Meter M_j
- Validator V_l

Payment note
------------
`allowcap_t` in the other modules is the pre-authorized payment limit, not the
final captured payment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

from .crypto import (
    PQKEMKeypair,
    PQSigKeypair,
    gen_ec_keypair,
    gen_pq_kem_keypair,
    gen_pq_sig_keypair,
    make_address_from_cls_pk,
    derive_pkid_from_public_key,
)


@dataclass
class User:
    """EV user / energy consumer."""

    user_id: str
    address: str
    home_domain: str
    cls_sk: Any
    cls_pk: Any
    pq_keys: PQSigKeypair
    balance: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def public_record(self) -> dict[str, Any]:
        """Return public registry record without private keys."""
        return {
            "user_id": self.user_id,
            "address": self.address,
            "home_domain": self.home_domain,
            "pq_pkid": self.pq_keys.pkid,
            "pq_backend": self.pq_keys.backend,
            "pq_algorithm": self.pq_keys.algorithm,
            "balance": float(self.balance),
            "metadata": dict(self.metadata),
        }


@dataclass
class Station:
    """Charging station / energy provider endpoint."""

    station_id: str
    foreign_domain: str
    operator_id: str
    beneficiary: str
    cls_sk: Any
    cls_pk: Any
    pq_sig_keys: PQSigKeypair | None
    kem_keys: PQKEMKeypair
    meter_ids: list[str] = field(default_factory=list)
    location: str = ""
    max_power_kw: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def public_record(self) -> dict[str, Any]:
        """Return public station record without private keys."""
        return {
            "station_id": self.station_id,
            "foreign_domain": self.foreign_domain,
            "operator_id": self.operator_id,
            "beneficiary": self.beneficiary,
            "station_classical_sig_algorithm": "ECDSA-SHA256",
            "station_classical_pkid": derive_pkid_from_public_key(self.cls_pk),
            "station_pq_sig_pkid": self.pq_sig_keys.pkid if self.pq_sig_keys is not None else "",
            "station_pq_sig_backend": self.pq_sig_keys.backend if self.pq_sig_keys is not None else "none",
            "station_pq_sig_algorithm": self.pq_sig_keys.algorithm if self.pq_sig_keys is not None else "none",
            "station_auth_mode": "hybrid-classical-pq" if self.pq_sig_keys is not None else "classical-only",
            "kem_pkid": self.kem_keys.pkid,
            "kem_backend": self.kem_keys.backend,
            "kem_algorithm": self.kem_keys.algorithm,
            "meter_ids": list(self.meter_ids),
            "location": self.location,
            "max_power_kw": float(self.max_power_kw),
            "metadata": dict(self.metadata),
        }


@dataclass
class Meter:
    """Meter / charger gateway that signs delivery receipts."""

    meter_id: str
    station_id: str
    foreign_domain: str
    sign_sk: Any
    sign_pk: Any
    metadata: dict[str, Any] = field(default_factory=dict)

    def public_record(self) -> dict[str, Any]:
        """Return public meter record without private keys."""
        return {
            "meter_id": self.meter_id,
            "station_id": self.station_id,
            "foreign_domain": self.foreign_domain,
            "receipt_sig_algorithm": "ECDSA-SHA256",
            "receipt_pkid": derive_pkid_from_public_key(self.sign_pk),
            "metadata": dict(self.metadata),
        }


@dataclass
class ValidatorNode:
    """Validator that verifies authorization projections and issues admission certificates."""

    validator_id: str
    domain: str
    address: str
    sign_sk: Any
    sign_pk: Any
    metadata: dict[str, Any] = field(default_factory=dict)

    def public_record(self) -> dict[str, Any]:
        """Return public validator record without private keys."""
        return {
            "validator_id": self.validator_id,
            "domain": self.domain,
            "address": self.address,
            "metadata": dict(self.metadata),
        }


def create_user(
    user_id: str,
    balance: float = 1000.0,
    home_domain: str = "OH",
    pq_backend: Literal["oqs", "mock-ed25519", "auto"] = "oqs",
    pq_algorithm: str = "ML-DSA-65",
    strict_pq: bool = True,
) -> User:
    """Create a user with real ECDSA and real OQS ML-DSA by default."""
    cls_kp = gen_ec_keypair()
    pq_kp = gen_pq_sig_keypair(
        algorithm=pq_algorithm,
        backend=pq_backend,
        strict=strict_pq,
    )
    address = make_address_from_cls_pk(cls_kp.pk)

    return User(
        user_id=user_id,
        address=address,
        home_domain=home_domain,
        cls_sk=cls_kp.sk,
        cls_pk=cls_kp.pk,
        pq_keys=pq_kp,
        balance=float(balance),
    )


def create_station(
    station_id: str,
    foreign_domain: str = "OF1",
    operator_id: Optional[str] = None,
    beneficiary: Optional[str] = None,
    sig_backend: Literal["oqs", "mock-ed25519", "auto"] = "oqs",
    sig_algorithm: str = "ML-DSA-65",
    kem_backend: Literal["oqs", "mock-sha256", "auto"] = "oqs",
    kem_algorithm: str = "ML-KEM-768",
    strict_pq: bool = True,
) -> Station:
    """Create a station with hybrid ECDSA + PQ signing and PQ KEM by default."""
    cls_kp = gen_ec_keypair()
    pq_sig_kp = gen_pq_sig_keypair(
        algorithm=sig_algorithm,
        backend=sig_backend,
        strict=strict_pq,
    )
    kem_kp = gen_pq_kem_keypair(
        algorithm=kem_algorithm,
        backend=kem_backend,
        strict=strict_pq,
    )

    return Station(
        station_id=station_id,
        foreign_domain=foreign_domain,
        operator_id=operator_id or f"OP_{foreign_domain}",
        beneficiary=beneficiary or f"BEN_{station_id}",
        cls_sk=cls_kp.sk,
        cls_pk=cls_kp.pk,
        pq_sig_keys=pq_sig_kp,
        kem_keys=kem_kp,
    )


def create_meter(
    meter_id: str,
    station_id: str,
    foreign_domain: str = "OF1",
) -> Meter:
    """Create a meter bound to a station with real ECDSA signing key."""
    cls_kp = gen_ec_keypair()

    return Meter(
        meter_id=meter_id,
        station_id=station_id,
        foreign_domain=foreign_domain,
        sign_sk=cls_kp.sk,
        sign_pk=cls_kp.pk,
    )


def create_validator(
    validator_id: str,
    domain: str = "CONSORTIUM",
) -> ValidatorNode:
    """Create a validator node with real ECDSA signing key."""
    cls_kp = gen_ec_keypair()
    address = make_address_from_cls_pk(cls_kp.pk)

    return ValidatorNode(
        validator_id=validator_id,
        domain=domain,
        address=address,
        sign_sk=cls_kp.sk,
        sign_pk=cls_kp.pk,
    )