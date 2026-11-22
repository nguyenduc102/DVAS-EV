"""Certified minimum-cardinality gate (minimality_exact.py).

Positive results for the 13 production predicates, plus negative controls
showing the gate can fail: a vacuous extra operand gets no witness, an
evaluator that reads a non-selected field is caught, and the authorization
result depends on the stated admissible domain (unregistered ENUM codes).
"""

from __future__ import annotations

import random

import pytest

from dbas_et.dvas import minimality_exact as mx
from dbas_et.dvas import predicates as P
from dbas_et.dvas.formal_checks import build_contexts
from dbas_et.dvas.predicates import PREDICATES, C, Cmp, Predicate
from dbas_et.dvas.workload import acn_sessions


@pytest.fixture(scope="module")
def ctx():
    return build_contexts(acn_sessions(max_rows=2))


@pytest.mark.parametrize("reason", list(PREDICATES))
def test_production_predicates_are_unique_minimum(ctx, reason):
    cert = mx.certify(reason, ctx, random.Random(1), randomisations=1)
    assert cert.s1_static and cert.s2_touched_subset
    assert cert.s3_mismatches == 0 and cert.s3_production_mismatches == 0
    assert all(w["domain"] != "NONE" for w in cert.witnesses)
    assert cert.status == "PROVED_UNIQUE_MINIMUM"


def test_only_payment_semantics_needs_the_adversarial_enum_domain(ctx):
    adv = []
    for reason in PREDICATES:
        cert = mx.certify(reason, ctx, random.Random(2), randomisations=1)
        adv += [(w["reason"], w["field"], w["verify_code_2"]) for w in cert.witnesses
                if w["domain"] == "adversarial_unregistered_enum"]
    assert adv == [("authorization", "payment_semantics", "ENCODING_ERROR")]


def test_pricing_fields_are_necessary_through_the_amount_only(ctx):
    cert = mx.certify("pricing", ctx, random.Random(3), randomisations=1)
    w = {x["field"]: x for x in cert.witnesses}
    for f in ("tariff_mode", "unit_price"):
        assert w[f]["g1"].startswith("(True") and w[f]["g2"].startswith("(True")  # same accept, different amount


def test_negative_control_vacuous_operand_is_not_certified(ctx):
    reason = "test:vacuous_extra_operand"
    PREDICATES[reason] = Predicate("P.test", P.TID_BINDING + (Cmp("EQ", C("user_id"), C("user_id"), "tautology"),))
    P._REQ_CACHE.clear()
    try:
        cert = mx.certify(reason, ctx, random.Random(4), randomisations=1)
        missing = [w["field"] for w in cert.witnesses if w["domain"] == "NONE"]
        assert missing == ["user_id"] and cert.status == "PARTIAL"
    finally:
        del PREDICATES[reason]
        P._REQ_CACHE.clear()


def test_negative_control_guarded_mapping_records_reads():
    gm = mx.GuardedMapping({"tid": "T", "user_id": "U"})
    _ = gm["tid"]
    _ = "user_id" in gm
    assert gm.touched == {"tid", "user_id"}


def test_negative_control_registered_only_domain_loses_payment_semantics_witness(ctx, monkeypatch):
    orig = mx.admissible_alternatives
    monkeypatch.setattr(mx, "admissible_alternatives",
                        lambda n, v: [x for x in orig(n, v) if x != mx.UNREGISTERED_ENUM])
    cert = mx.certify("authorization", ctx, random.Random(5), randomisations=1)
    missing = [w["field"] for w in cert.witnesses if w["domain"] == "NONE"]
    assert missing == ["payment_semantics"] and cert.status == "PARTIAL"
