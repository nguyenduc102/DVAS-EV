"""
Build DVAS-EV committed layout values from legacy capsules or workload rows.

This is the single explicit normalisation boundary: dataset floats are
converted to 6-decimal Decimals (ROUND_HALF_EVEN) here and nowhere else.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..capsule import CanonicalCapsule
from .canonical import to_fixed6
from .schema import LAYOUT_SCHEMA_ID, PROTOCOL_VERSION_VALUE

DEFAULT_CURRENCY = "TOKEN"


def layout_values_from_capsule(
    capsule: CanonicalCapsule,
    *,
    currency: str = DEFAULT_CURRENCY,
    evse_id: str | None = None,
) -> dict[str, Any]:
    """Map a legacy ``CanonicalCapsule`` onto the DVAS-EV committed layout."""
    return {
        "protocol_version": PROTOCOL_VERSION_VALUE,
        "schema_version": LAYOUT_SCHEMA_ID,
        "tid": capsule.trade_id,
        "created_at": int(capsule.created_at),
        "user_id": capsule.user_id,
        "user_account": capsule.user_address,
        "home_operator": capsule.home_domain,
        "station_id": capsule.station_id,
        "meter_id": capsule.meter_id,
        "foreign_operator": capsule.foreign_domain,
        "beneficiary": capsule.beneficiary,
        "evse_id": evse_id,
        "tariff_id": capsule.tariff_id,
        "tariff_version": capsule.tariff_version,
        "tariff_mode": capsule.tariff_mode,
        "unit_price": to_fixed6(capsule.unit_price),
        "currency": currency,
        "requested_kwh": to_fixed6(capsule.requested_kwh),
        "cap_kwh": to_fixed6(capsule.cap_kwh),
        "preauth_limit": to_fixed6(capsule.preauth_limit_t),
        "tw_start": int(capsule.tw_start),
        "tw_end": int(capsule.tw_end),
        "paytok": capsule.paytok_t,
        "payment_semantics": "RESERVE_RELEASE",
        "nonce_u": capsule.nonce_u,
        "nonce_s": capsule.nonce_s,
    }


def with_overrides(values: Mapping[str, Any], **overrides: Any) -> dict[str, Any]:
    out = dict(values)
    out.update(overrides)
    return out
