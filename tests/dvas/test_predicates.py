"""Section 2: PA-MSP dependency registry and predicate evaluation."""

from __future__ import annotations

from decimal import Decimal

import pytest

from dbas_et.dvas.predicates import (
    PREDICATES,
    committed_operands,
    dependency_table,
    evaluate,
    predicate_for,
    required_fields,
)
from dbas_et.dvas.schema import LAYOUT_V1, PRE, REGISTRY

REQUIRED_REASONS = {"authorization", "replay", "station_meter_binding", "pricing", "time_window", "delivery_cap",
                    "reserve_amount", "settlement", "dispute:over_cap", "dispute:tariff_mismatch",
                    "dispute:time_window", "dispute:amount_exceeds_preauth", "dispute:replay"}


def test_registry_covers_required_reasons():
    assert REQUIRED_REASONS <= set(PREDICATES)


@pytest.mark.parametrize("reason", sorted(REQUIRED_REASONS))
def test_required_fields_deterministic_and_committed(reason):
    a = required_fields(LAYOUT_V1, reason)
    b = required_fields(LAYOUT_V1, reason)
    assert a == b and len(a) == len(set(a)) and a
    ids = [REGISTRY.spec(n).field_id for n in a]
    assert ids == sorted(ids)
    assert all(REGISTRY.spec(n).lifecycle == PRE for n in a)
    assert set(a) == set(committed_operands(PREDICATES[reason]))


def test_expected_dependency_sets():
    assert required_fields(LAYOUT_V1, "delivery_cap") == ("tid", "cap_kwh")
    assert required_fields(LAYOUT_V1, "time_window") == ("tid", "tw_start", "tw_end")
    assert set(required_fields(LAYOUT_V1, "pricing")) == {"tid", "tariff_id", "tariff_version", "tariff_mode",
                                                           "unit_price", "currency"}
    s = set(required_fields(LAYOUT_V1, "settlement"))
    for sub in ("station_meter_binding", "pricing", "time_window", "delivery_cap", "reserve_amount"):
        assert set(required_fields(LAYOUT_V1, sub)) <= s
    # settlement does not need user identity: it is not disclosed to verifiers
    assert not s & {"user_id", "user_account", "home_operator", "nonce_u", "nonce_s"}


def test_dependency_table_has_operands_per_atom():
    rows = dependency_table()
    assert rows and all(r["atom"] for r in rows)


def _settlement_inputs():
    committed = {"tid": "t", "station_id": "S", "meter_id": "M", "foreign_operator": "OF", "beneficiary": "B",
                 "tariff_id": "T", "tariff_version": "v1", "tariff_mode": "ENERGY_ONLY",
                 "unit_price": Decimal("0.5"), "currency": "TOKEN", "cap_kwh": Decimal("10"),
                 "preauth_limit": Decimal("10"), "tw_start": 100, "tw_end": 200, "paytok": "p"}
    evidence = {"receipt_tid": "t", "receipt_station_id": "S", "receipt_meter_id": "M", "applied_tariff_id": "T",
                "applied_tariff_version": "v1", "settlement_currency": "TOKEN", "delivered_kwh": Decimal("8"),
                "ts_start": 110, "ts_end": 190, "connection_duration_s": 80, "active_charging_duration_s": 80,
                "parking_duration_s": 0, "effective_limit": Decimal("10"), "held_amount": Decimal("10"),
                "payee": "B", "ledger_paytok": "p", "sid": "s", "dr_digest": "d"}
    rel = {"meter_bound_to_station": lambda m, s: True, "station_operated_by": lambda s, o: True}
    return committed, evidence, rel


def test_settlement_predicate_accepts_and_derives_amount():
    c, e, rel = _settlement_inputs()
    res = evaluate(predicate_for("settlement"), c, e, rel)
    assert res.ok, res
    assert res.outputs["amount"] == Decimal("4.000000")


@pytest.mark.parametrize("field,ev_update,expect", [
    ("cap_kwh", {"delivered_kwh": Decimal("12")}, "energy_within_cap"),
    ("tw_end", {"ts_end": 250}, "end_in_window"),
    ("tariff_id", {"applied_tariff_id": "OTHER"}, "tariff_id_match"),
])
def test_settlement_predicate_rejects(field, ev_update, expect):
    c, e, rel = _settlement_inputs()
    res = evaluate(predicate_for("settlement"), c, {**e, **ev_update}, rel)
    assert not res.ok and expect in res.failed


def test_invalid_derived_output_rejects_instead_of_raising():
    c, e, rel = _settlement_inputs()
    res = evaluate(predicate_for("settlement"), {**c, "unit_price": Decimal("-1")}, e, rel)
    assert not res.ok and any(f.startswith("output_amount_invalid") for f in res.failed)


def test_missing_operand_is_never_defaulted():
    c, e, rel = _settlement_inputs()
    c.pop("cap_kwh")
    res = evaluate(predicate_for("settlement"), c, {**e, "delivered_kwh": Decimal("12")}, rel)
    assert not res.ok and "committed:cap_kwh" in res.missing


def test_legacy_match_defaults_missing_cap_contrast():
    """The legacy Match substitutes delivered_kwh for a missing cap and accepts."""
    from dbas_et.payments import DeliveryReceipt
    from dbas_et.projections import ProjectionView
    from dbas_et.settlement_verifier import evaluate_match_checks

    receipt = DeliveryReceipt(trade_id="t", sid_t="s", station_id="S", meter_id="M", foreign_domain="OF",
                              delivered_kwh=12.0, ts_start=110, ts_end=190, tariff_id="T", tariff_version="v1",
                              tariff_mode="ENERGY_ONLY")
    ar = {"trade_id": "t", "rho_t": "r", "station_id": "S", "meter_id": "M", "tariff_id": "T",
          "tariff_version": "v1", "tw_start": 100, "tw_end": 200, "unit_price": 0.5, "effective_preauth_limit_t": 10}
    checks, _ = evaluate_match_checks(ar_t=ar, receipt=receipt, rho_t="r", S_view=ProjectionView("S", "t", []),
                                      meter_samples=[], tariff_record={}, opened_payloads={})
    assert all(checks.values())  # legacy: over-cap accepted when the cap operand is absent
