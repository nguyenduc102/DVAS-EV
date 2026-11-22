"""
Payment, delivery receipt, tariff, and top-up utilities for DBAS-ET.

Terminology
-----------
preauth_limit_t:
    Pre-authorized payment limit / held amount cap. Not captured payment.

captured_amount:
    Actual amount released to the station after a valid delivery receipt.

released_unused_hold:
    Unused held amount returned to the user after settlement.

Top-up
------
A top-up is a signed authorization event that increases the effective
pre-authorized limit without recommitting the original capsule root rho_t.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, replace
from typing import Any, Literal

from .capsule import CanonicalCapsule
from .crypto import H, H_hex, ecdsa_sign, ecdsa_verify
from .entities import Meter, User


TariffMode = Literal[
    "ENERGY_ONLY",
    "ENERGY_ACTIVE_TIME",
    "ENERGY_ACTIVE_PARKING",
    "CONNECTION_TIME",
]


@dataclass(frozen=True)
class TariffResult:
    """Tariff evaluation result."""

    amount: float
    energy_component: float
    active_time_component: float
    parking_component: float
    connection_time_component: float
    flat_fee: float
    tax: float
    mode: str

    def to_record(self) -> dict[str, Any]:
        return asdict(self)


def eval_tariff_amount(
    delivered_kwh: float,
    unit_price: float,
    mode: str = "ENERGY_ONLY",
    connection_duration_s: int = 0,
    active_charging_duration_s: int = 0,
    parking_duration_s: int = 0,
    active_time_rate_per_hour: float = 0.03,
    parking_rate_per_hour: float = 0.02,
    connection_time_rate_per_hour: float = 0.01,
    flat_fee: float = 0.0,
    tax_rate: float = 0.0,
) -> TariffResult:
    """
    Evaluate charging tariff.

    This is a deterministic simulation tariff evaluator. It is not an OCPI
    tariff engine. Later workload modules may map OCPI-like tariff fields into
    these parameters.
    """
    if delivered_kwh < 0:
        raise ValueError("delivered_kwh must be non-negative")
    if unit_price < 0:
        raise ValueError("unit_price must be non-negative")

    energy_component = float(delivered_kwh) * float(unit_price)

    active_hours = max(0, int(active_charging_duration_s)) / 3600.0
    parking_hours = max(0, int(parking_duration_s)) / 3600.0
    connection_hours = max(0, int(connection_duration_s)) / 3600.0

    active_time_component = 0.0
    parking_component = 0.0
    connection_time_component = 0.0

    if mode == "ENERGY_ONLY":
        pass
    elif mode == "ENERGY_ACTIVE_TIME":
        active_time_component = active_hours * float(active_time_rate_per_hour)
    elif mode == "ENERGY_ACTIVE_PARKING":
        active_time_component = active_hours * float(active_time_rate_per_hour)
        parking_component = parking_hours * float(parking_rate_per_hour)
    elif mode == "CONNECTION_TIME":
        connection_time_component = connection_hours * float(connection_time_rate_per_hour)
    else:
        raise ValueError(f"unsupported tariff mode: {mode}")

    subtotal = (
        energy_component
        + active_time_component
        + parking_component
        + connection_time_component
        + float(flat_fee)
    )
    tax = subtotal * float(tax_rate)
    amount = subtotal + tax

    return TariffResult(
        amount=round(float(amount), 6),
        energy_component=round(float(energy_component), 6),
        active_time_component=round(float(active_time_component), 6),
        parking_component=round(float(parking_component), 6),
        connection_time_component=round(float(connection_time_component), 6),
        flat_fee=round(float(flat_fee), 6),
        tax=round(float(tax), 6),
        mode=mode,
    )


def build_session_id(
    capsule: CanonicalCapsule,
    nonce: str | None = None,
    rho_t: str = "",
) -> str:
    """Build deterministic session id from committed transaction context.

    The session is bound to trade_id and to the capsule root rho_t. rho_t is
    optional only for the older call sites that do not pass it.
    """
    session_nonce = nonce or uuid.uuid4().hex
    return H_hex(
        "H_SESSION_ID",
        {
            "trade_id": capsule.trade_id,
            "rho_t": str(rho_t),
            "station_id": capsule.station_id,
            "meter_id": capsule.meter_id,
            "nonce": session_nonce,
        },
    )[:40]


@dataclass(frozen=True)
class DeliveryReceipt:
    """
    Meter-signed delivery receipt DR_t.

    The receipt binds actual delivery evidence to the committed transaction.
    """

    trade_id: str
    sid_t: str
    station_id: str
    meter_id: str
    foreign_domain: str

    delivered_kwh: float
    ts_start: int
    ts_end: int

    tariff_id: str
    tariff_version: str
    tariff_mode: str

    connection_duration_s: int = 0
    active_charging_duration_s: int = 0
    parking_duration_s: int = 0

    nonce_m: str = ""
    sig_m: bytes = b""

    def unsigned_record(self) -> dict[str, Any]:
        """Return receipt record excluding meter signature."""
        return {
            "trade_id": self.trade_id,
            "sid_t": self.sid_t,
            "station_id": self.station_id,
            "meter_id": self.meter_id,
            "foreign_domain": self.foreign_domain,
            "delivered_kwh": float(self.delivered_kwh),
            "ts_start": int(self.ts_start),
            "ts_end": int(self.ts_end),
            "tariff_id": self.tariff_id,
            "tariff_version": self.tariff_version,
            "tariff_mode": self.tariff_mode,
            "connection_duration_s": int(self.connection_duration_s),
            "active_charging_duration_s": int(self.active_charging_duration_s),
            "parking_duration_s": int(self.parking_duration_s),
            "nonce_m": self.nonce_m,
        }

    def signed_record(self) -> dict[str, Any]:
        """Return receipt record including signature hex."""
        record = self.unsigned_record()
        record["sig_m_hex"] = self.sig_m.hex()
        return record


def build_receipt_message(receipt: DeliveryReceipt) -> bytes:
    """Build canonical signed message for a delivery receipt."""
    return H("H_DELIVERY_RECEIPT_TO_SIGN", receipt.unsigned_record())


def sign_delivery_receipt(meter: Meter, receipt: DeliveryReceipt) -> DeliveryReceipt:
    """Sign a receipt using the meter signing key."""
    sig = ecdsa_sign(meter.sign_sk, build_receipt_message(receipt))
    return replace(receipt, sig_m=sig)


def verify_delivery_receipt(meter: Meter, receipt: DeliveryReceipt) -> bool:
    """Verify meter signature on a delivery receipt."""
    return ecdsa_verify(meter.sign_pk, build_receipt_message(receipt), receipt.sig_m)


def receipt_hash(receipt: DeliveryReceipt) -> str:
    """Hash signed delivery receipt for replay detection."""
    return H_hex("H_SIGNED_DELIVERY_RECEIPT", receipt.signed_record())


def build_delivery_receipt(
    capsule: CanonicalCapsule,
    sid_t: str,
    meter: Meter,
    delivered_kwh: float,
    ts_start: int,
    ts_end: int,
    tariff_id: str | None = None,
    tariff_version: str | None = None,
    tariff_mode: str | None = None,
    connection_duration_s: int = 0,
    active_charging_duration_s: int = 0,
    parking_duration_s: int = 0,
    nonce_m: str | None = None,
) -> DeliveryReceipt:
    """Build and sign a delivery receipt for a capsule/session."""
    unsigned = DeliveryReceipt(
        trade_id=capsule.trade_id,
        sid_t=sid_t,
        station_id=capsule.station_id,
        meter_id=meter.meter_id,
        foreign_domain=capsule.foreign_domain,
        delivered_kwh=float(delivered_kwh),
        ts_start=int(ts_start),
        ts_end=int(ts_end),
        tariff_id=tariff_id or capsule.tariff_id,
        tariff_version=tariff_version or capsule.tariff_version,
        tariff_mode=tariff_mode or capsule.tariff_mode,
        connection_duration_s=int(connection_duration_s),
        active_charging_duration_s=int(active_charging_duration_s),
        parking_duration_s=int(parking_duration_s),
        nonce_m=nonce_m or uuid.uuid4().hex,
        sig_m=b"",
    )
    return sign_delivery_receipt(meter, unsigned)


@dataclass(frozen=True)
class TopUpAuthorizationEvent:
    """
    Signed dynamic pre-authorization top-up event.

    This event increases the effective pre-authorized limit without changing
    the committed capsule root rho_t.
    """

    trade_id: str
    rho_t: str
    sid_t: str
    owner_address: str
    old_limit: float
    delta_limit: float
    new_limit: float
    reason: str
    nonce: str
    created_at: int
    sigma_u: bytes = b""

    def unsigned_record(self) -> dict[str, Any]:
        """Return top-up record excluding signature."""
        return {
            "trade_id": self.trade_id,
            "rho_t": self.rho_t,
            "sid_t": self.sid_t,
            "owner_address": self.owner_address,
            "old_limit": float(self.old_limit),
            "delta_limit": float(self.delta_limit),
            "new_limit": float(self.new_limit),
            "reason": self.reason,
            "nonce": self.nonce,
            "created_at": int(self.created_at),
        }

    def signed_record(self) -> dict[str, Any]:
        """Return top-up record including signature hex."""
        record = self.unsigned_record()
        record["sigma_u_hex"] = self.sigma_u.hex()
        return record


def build_topup_message(event: TopUpAuthorizationEvent) -> bytes:
    """Build canonical signed message for top-up authorization."""
    return H("H_TOPUP_AUTHORIZATION_TO_SIGN", event.unsigned_record())


def make_topup_event(
    user: User,
    trade_id: str,
    rho_t: str,
    sid_t: str,
    old_limit: float,
    delta_limit: float,
    reason: str = "increase_preauthorized_limit",
) -> TopUpAuthorizationEvent:
    """Create and sign a top-up authorization event."""
    if delta_limit <= 0:
        raise ValueError("delta_limit must be positive")

    event = TopUpAuthorizationEvent(
        trade_id=trade_id,
        rho_t=rho_t,
        sid_t=sid_t,
        owner_address=user.address,
        old_limit=float(old_limit),
        delta_limit=float(delta_limit),
        new_limit=float(old_limit + delta_limit),
        reason=reason,
        nonce=uuid.uuid4().hex,
        created_at=int(time.time()),
        sigma_u=b"",
    )

    sig = ecdsa_sign(user.cls_sk, build_topup_message(event))
    return replace(event, sigma_u=sig)


def verify_topup_event(user: User, event: TopUpAuthorizationEvent) -> bool:
    """Verify user signature and arithmetic consistency of a top-up event."""
    if event.owner_address != user.address:
        return False

    if event.delta_limit <= 0:
        return False

    if abs(event.new_limit - (event.old_limit + event.delta_limit)) > 1e-9:
        return False

    return ecdsa_verify(user.cls_pk, build_topup_message(event), event.sigma_u)


def topup_hash(event: TopUpAuthorizationEvent) -> str:
    """Hash signed top-up event for audit traces."""
    return H_hex("H_SIGNED_TOPUP_EVENT", event.signed_record())