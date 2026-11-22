"""Section 15: OCPI/OCPP semantic adapter (mapping demonstration, not compliance)."""

from __future__ import annotations

import copy
import json
from decimal import Decimal
from pathlib import Path

import pytest

from dbas_et.dvas.profiles import PROFILES
from dbas_et.dvas.protocol import DvasEnvironment
from dbas_et.dvas.standards_adapter import (
    UnsupportedMapping,
    map_ocpi_tariff,
    map_ocpp_transaction,
    session_spec_from_standards,
)

FX = Path(__file__).resolve().parents[1] / "fixtures" / "standards"


def _load(name):
    return json.loads((FX / name).read_text())


@pytest.fixture
def objs():
    return dict(token=_load("ocpi_token.json"), location=_load("ocpi_location.json"),
                tariff=_load("ocpi_tariff.json"), auth_request=_load("dvas_authorization_request.json"),
                transaction_events=_load("ocpp_transaction_events.json"))


def test_tariff_mapping(objs):
    m = map_ocpi_tariff(objs["tariff"])
    assert m["tariff_mode"] == "ENERGY_ACTIVE_TIME" and m["unit_price"] == Decimal("0.32") and m["currency"] == "EUR"


def test_unsupported_tariff_rejected_not_silently_mapped(objs):
    t = copy.deepcopy(objs["tariff"])
    t["elements"][0]["price_components"][1]["price"] = 0.5
    with pytest.raises(UnsupportedMapping):
        map_ocpi_tariff(t)
    t["elements"][0]["price_components"] = [{"type": "ENERGY", "price": 0.3}, {"type": "FLAT", "price": 1}]
    with pytest.raises(UnsupportedMapping):
        map_ocpi_tariff(t)


def test_ocpp_delivery_mapping(objs):
    d = map_ocpp_transaction(objs["transaction_events"])
    assert d["delivered_kwh"] == Decimal("14.083")
    assert d["connection_duration_s"] == 10200 and d["active_charging_duration_s"] == 8400
    assert d["parking_duration_s"] == 1800 and d["meter_values_digest"]


def test_end_to_end_settlement_from_standards_objects(objs):
    spec = session_spec_from_standards(tid="ocpi-tx-0001", evse_uid="EVSE-1", **objs)
    env = DvasEnvironment(profile=PROFILES["C3"])
    r = env.run(spec)
    assert r.ok, r
    assert r.captured == spec.expected_amount == Decimal("4.576560")
    # signed-meter-value digest is bound into DR_private and hence into the meter-signed h_priv
    s = env.session(spec)
    assert spec.extra["meter_values_digest"]


def test_cross_operator_mapping(objs):
    spec = session_spec_from_standards(tid="ocpi-tx-0002", evse_uid="EVSE-1", **objs)
    assert spec.home_operator == "DE*EMA" and spec.foreign_operator == "NL*CPB"
    assert spec.evse_id == "NL*CPB*E0001*1"


def test_tariff_changed_after_authorization_is_detected(objs):
    """CPO bills with a different tariff version than the one committed at authorization."""
    spec = session_spec_from_standards(tid="ocpi-tx-0003", evse_uid="EVSE-1", **objs)
    env = DvasEnvironment(profile=PROFILES["C0"])
    s = env.session(spec)
    s.commit(); assert s.authorize().ok; assert s.open_session().ok
    s.deliver(applied_tariff_version="2026-10-01T09:00:00Z")
    assert s.submit_receipt().ok
    outs = s.verify()
    assert all(not o.ok and "tariff_version_match" in o.reason for o in outs)


def test_wrong_evse_and_bad_transactions(objs):
    with pytest.raises(UnsupportedMapping):
        session_spec_from_standards(tid="x", evse_uid="EVSE-404", **objs)
    ev = copy.deepcopy(objs["transaction_events"])
    ev[2]["transactionInfo"]["transactionId"] = "TX-OTHER"
    with pytest.raises(UnsupportedMapping):
        map_ocpp_transaction(ev)
    ev = copy.deepcopy(objs["transaction_events"])
    ev[2]["meterValue"][0]["sampledValue"][0]["value"] = 1
    with pytest.raises(UnsupportedMapping):
        map_ocpp_transaction(ev)
