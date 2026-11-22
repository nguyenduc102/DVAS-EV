"""Checked minimality analysis: classifications must stay as established unless evidence changes."""

from __future__ import annotations

import pytest

from dbas_et.dvas.formal_checks import build_contexts
from dbas_et.dvas.minimality import VACUITY_LEMMAS, classify, singleton_domain
from dbas_et.dvas.predicates import PREDICATES
from dbas_et.dvas.workload import acn_sessions

EXPECTED = {r: "BOOLEAN_MINIMAL" for r in PREDICATES}
EXPECTED["authorization"] = "NOT_MINIMAL"
EXPECTED["pricing"] = "DECISION_MINIMAL_ONLY"


@pytest.fixture(scope="module")
def ctx():
    return [c for _, _, c in build_contexts(acn_sessions(max_rows=3))]


@pytest.mark.parametrize("reason", list(PREDICATES))
def test_classification(ctx, reason):
    assert classify(reason, ctx).classification == EXPECTED[reason]


def test_certificates_are_the_documented_ones(ctx):
    auth = {r["field"]: r for r in classify("authorization", ctx).rows}
    assert auth["payment_semantics"]["decision_nonnecessity_certificate"] == "SINGLETON_DOMAIN"
    assert singleton_domain("payment_semantics")
    pr = {r["field"]: r for r in classify("pricing", ctx).rows}
    for f in ("tariff_mode", "unit_price"):
        assert not pr[f]["boolean_witness"] and pr[f]["decision_witness"]
        assert pr[f]["boolean_nonnecessity_certificate"].startswith("VACUOUS_ATOM")
    assert "amount_defined" in VACUITY_LEMMAS


def test_production_selector_unchanged():
    """The analysis never alters the runtime selector (sufficiency only)."""
    from dbas_et.dvas.predicates import required_fields
    from dbas_et.dvas.schema import LAYOUT_V1

    assert "payment_semantics" in required_fields(LAYOUT_V1, "authorization")
    assert {"tariff_mode", "unit_price"} <= set(required_fields(LAYOUT_V1, "pricing"))
