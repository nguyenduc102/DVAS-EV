"""
Deterministic Decimal tariff evaluation shared by all verifiers.

Mirrors ``dbas_et.payments.eval_tariff_amount`` (same modes and default
per-hour rates) but uses exact Decimal arithmetic with one final
ROUND_HALF_EVEN quantisation to 6 decimals, so that independent verifiers
always derive bit-identical amounts.
"""

from __future__ import annotations

from decimal import ROUND_HALF_EVEN, Decimal

ACTIVE_TIME_RATE_PER_HOUR = Decimal("0.03")
PARKING_RATE_PER_HOUR = Decimal("0.02")
CONNECTION_TIME_RATE_PER_HOUR = Decimal("0.01")
_Q = Decimal("0.000001")
_H = Decimal(3600)


def tariff_amount(
    *,
    mode: str,
    unit_price: Decimal,
    delivered_kwh: Decimal,
    connection_duration_s: int = 0,
    active_charging_duration_s: int = 0,
    parking_duration_s: int = 0,
) -> Decimal:
    if delivered_kwh < 0:
        raise ValueError("delivered_kwh must be non-negative")
    if unit_price < 0:
        raise ValueError("unit_price must be non-negative")
    amount = Decimal(delivered_kwh) * Decimal(unit_price)
    active_h = Decimal(max(0, int(active_charging_duration_s))) / _H
    parking_h = Decimal(max(0, int(parking_duration_s))) / _H
    connection_h = Decimal(max(0, int(connection_duration_s))) / _H
    if mode == "ENERGY_ONLY":
        pass
    elif mode == "ENERGY_ACTIVE_TIME":
        amount += active_h * ACTIVE_TIME_RATE_PER_HOUR
    elif mode == "ENERGY_ACTIVE_PARKING":
        amount += active_h * ACTIVE_TIME_RATE_PER_HOUR + parking_h * PARKING_RATE_PER_HOUR
    elif mode == "CONNECTION_TIME":
        amount += connection_h * CONNECTION_TIME_RATE_PER_HOUR
    else:
        raise ValueError(f"unsupported tariff mode {mode}")
    return amount.quantize(_Q, rounding=ROUND_HALF_EVEN)
