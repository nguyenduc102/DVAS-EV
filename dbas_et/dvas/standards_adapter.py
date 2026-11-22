"""
Lightweight OCPI / OCPP semantic-mapping adapter.

A mapping demo, not an OCPI/OCPP backend and not a compliance test.  It maps
representative structured objects onto DVAS-EV semantics:

  OCPI Token + Location/EVSE + Tariff + authorization request
        -> committed capsule C_t (layout values)
  OCPI Tariff price components
        -> committed pricing fields (tariff_id/version/mode/unit_price/currency)
  OCPI Location.evses[].evse_id
        -> station / EVSE binding (station_id, evse_id)
  OCPP 2.0.1 TransactionEvent (Started/Updated/Ended) with
  Energy.Active.Import.Register sampled values and signedMeterValue
        -> authenticated delivery evidence (delivered_kwh, ts_start, ts_end,
           durations) + meter_values_digest = H(signedMeterData) inside
           DR_private (and therefore inside the meter-signed h_priv).

Limitations: OCMF/EDL signed meter values are not parsed or verified;
tariffs whose TIME/PARKING_TIME prices differ from the protocol's fixed
per-hour rates are rejected as unsupported rather than silently mapped.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from decimal import Decimal
from typing import Any, Mapping

from .canonical import to_fixed6
from .tariff import ACTIVE_TIME_RATE_PER_HOUR, CONNECTION_TIME_RATE_PER_HOUR, PARKING_RATE_PER_HOUR
from .workload import SessionSpec


class UnsupportedMapping(ValueError):
    pass


def _ts(s: str) -> int:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise UnsupportedMapping(f"timestamp without timezone: {s}")
    return int(dt.timestamp())


def map_ocpi_tariff(tariff: Mapping[str, Any]) -> dict[str, Any]:
    comps: dict[str, Decimal] = {}
    for el in tariff.get("elements", []):
        if el.get("restrictions"):
            raise UnsupportedMapping("tariff restrictions are not supported by the demo adapter")
        for pc in el.get("price_components", []):
            comps[pc["type"]] = Decimal(str(pc["price"]))
    if "ENERGY" not in comps:
        raise UnsupportedMapping("tariff without ENERGY component")
    kinds = set(comps)
    if kinds == {"ENERGY"}:
        mode = "ENERGY_ONLY"
    elif kinds == {"ENERGY", "TIME"}:
        mode = "ENERGY_ACTIVE_TIME"
        _require(comps["TIME"], ACTIVE_TIME_RATE_PER_HOUR, "TIME")
    elif kinds == {"ENERGY", "TIME", "PARKING_TIME"}:
        mode = "ENERGY_ACTIVE_PARKING"
        _require(comps["TIME"], ACTIVE_TIME_RATE_PER_HOUR, "TIME")
        _require(comps["PARKING_TIME"], PARKING_RATE_PER_HOUR, "PARKING_TIME")
    elif kinds == {"ENERGY", "FLAT"}:
        raise UnsupportedMapping("FLAT fee not supported by the demo tariff evaluator")
    else:
        raise UnsupportedMapping(f"unsupported price components {sorted(kinds)}")
    return {
        "tariff_id": tariff["id"],
        "tariff_version": tariff["last_updated"],
        "tariff_mode": mode,
        "unit_price": to_fixed6(comps["ENERGY"]),
        "currency": tariff["currency"],
    }


def _require(got: Decimal, expected: Decimal, kind: str) -> None:
    if got != expected:
        raise UnsupportedMapping(f"{kind} price {got}/h differs from protocol rate {expected}/h")


def map_ocpi_authorization(
    *,
    token: Mapping[str, Any],
    location: Mapping[str, Any],
    evse_uid: str,
    tariff: Mapping[str, Any],
    auth_request: Mapping[str, Any],
) -> dict[str, Any]:
    """Map OCPI Token/Location/Tariff + authorization request to capsule semantics."""
    evse = next((e for e in location.get("evses", []) if e["uid"] == evse_uid), None)
    if evse is None:
        raise UnsupportedMapping(f"EVSE {evse_uid} not in location {location.get('id')}")
    if tariff["id"] not in evse["connectors"][0].get("tariff_ids", []):
        raise UnsupportedMapping("tariff not offered on this EVSE")
    pricing = map_ocpi_tariff(tariff)
    return {
        "user_id": token["contract_id"],
        "home_operator": f"{token['country_code']}*{token['party_id']}",
        "station_id": f"{location['country_code']}*{location['party_id']}*{location['id']}*{evse_uid}",
        "foreign_operator": f"{location['country_code']}*{location['party_id']}",
        "evse_id": evse["evse_id"],
        "meter_id": evse["meter_id"],
        "authorization_reference": auth_request["authorization_reference"],
        "requested_kwh": to_fixed6(auth_request["requested_kwh"]),
        "cap_kwh": to_fixed6(auth_request["max_kwh"]),
        "preauth_limit": to_fixed6(auth_request["preauthorized_amount"]),
        "tw_start": _ts(auth_request["valid_from"]),
        "tw_end": _ts(auth_request["valid_until"]),
        **pricing,
    }


def map_ocpp_transaction(events: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Map an OCPP 2.0.1 TransactionEvent sequence to delivery evidence."""
    by = {e["eventType"]: e for e in events if e["eventType"] in ("Started", "Ended")}
    if set(by) != {"Started", "Ended"}:
        raise UnsupportedMapping("need Started and Ended TransactionEvents")
    tx = {e["transactionInfo"]["transactionId"] for e in events}
    if len(tx) != 1:
        raise UnsupportedMapping("events from more than one transaction")

    def energy_wh(ev: Mapping[str, Any]) -> tuple[Decimal, str | None]:
        for mv in ev.get("meterValue", []):
            for sv in mv.get("sampledValue", []):
                if sv.get("measurand", "Energy.Active.Import.Register") == "Energy.Active.Import.Register":
                    mult = Decimal(10) ** int(sv.get("unitOfMeasure", {}).get("multiplier", 0))
                    unit = sv.get("unitOfMeasure", {}).get("unit", "Wh")
                    v = Decimal(str(sv["value"])) * mult
                    v = v * 1000 if unit == "kWh" else v
                    smv = sv.get("signedMeterValue", {}).get("signedMeterData")
                    return v, smv
        raise UnsupportedMapping("no Energy.Active.Import.Register sample")

    start_wh, smv_start = energy_wh(by["Started"])
    end_wh, smv_end = energy_wh(by["Ended"])
    if end_wh < start_wh:
        raise UnsupportedMapping("meter register decreased")
    t0, t1 = _ts(by["Started"]["timestamp"]), _ts(by["Ended"]["timestamp"])
    done = t1
    for e in sorted(events, key=lambda e: _ts(e["timestamp"])):
        state = e.get("transactionInfo", {}).get("chargingState")
        if e["eventType"] == "Updated" and state in ("SuspendedEV", "EVConnected", "Idle"):
            done = _ts(e["timestamp"])
            break
    signed = "|".join(x for x in (smv_start, smv_end) if x)
    return {
        "transaction_id": tx.pop(),
        "delivered_kwh": to_fixed6((end_wh - start_wh) / 1000),
        "ts_start": t0,
        "ts_end": t1,
        "connection_duration_s": t1 - t0,
        "active_charging_duration_s": done - t0,
        "parking_duration_s": t1 - done,
        "meter_values_digest": hashlib.sha256(signed.encode()).hexdigest() if signed else None,
    }


def session_spec_from_standards(
    *,
    tid: str,
    token: Mapping[str, Any],
    location: Mapping[str, Any],
    evse_uid: str,
    tariff: Mapping[str, Any],
    auth_request: Mapping[str, Any],
    transaction_events: list[Mapping[str, Any]],
) -> SessionSpec:
    a = map_ocpi_authorization(token=token, location=location, evse_uid=evse_uid, tariff=tariff,
                               auth_request=auth_request)
    d = map_ocpp_transaction(transaction_events)
    from .tariff import tariff_amount

    expected = tariff_amount(mode=a["tariff_mode"], unit_price=a["unit_price"], delivered_kwh=d["delivered_kwh"],
                             connection_duration_s=d["connection_duration_s"],
                             active_charging_duration_s=d["active_charging_duration_s"],
                             parking_duration_s=d["parking_duration_s"])
    return SessionSpec(
        source="OCPI/OCPP-fixture", row_index=0, session_ref=d["transaction_id"], tid=tid,
        user_id=a["user_id"], home_operator=a["home_operator"], station_id=a["station_id"],
        foreign_operator=a["foreign_operator"], meter_id=a["meter_id"], beneficiary=f"BEN_{a['foreign_operator']}",
        evse_id=a["evse_id"], tariff_id=a["tariff_id"], tariff_version=a["tariff_version"],
        tariff_mode=a["tariff_mode"], unit_price=a["unit_price"], currency=a["currency"],
        requested_kwh=a["requested_kwh"], cap_kwh=a["cap_kwh"], preauth_limit=a["preauth_limit"],
        tw_start=a["tw_start"], tw_end=a["tw_end"], nonce_u=f"ocpi-{a['authorization_reference']}",
        nonce_s=f"ocpp-{d['transaction_id']}", created_at=a["tw_start"], delivered_kwh=d["delivered_kwh"],
        ts_start=d["ts_start"], ts_end=d["ts_end"], connection_duration_s=d["connection_duration_s"],
        active_charging_duration_s=d["active_charging_duration_s"], parking_duration_s=d["parking_duration_s"],
        expected_amount=expected, extra={"meter_values_digest": d["meter_values_digest"],
                                         "authorization_reference": a["authorization_reference"]},
    )
