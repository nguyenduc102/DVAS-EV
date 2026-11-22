"""Formal properties of PAM-Proof through the Setup/Commit/Select/Open/Verify API."""

from __future__ import annotations

import random

import pytest

from dbas_et.dvas.formal_checks import (
    build_contexts,
    check_binding,
    check_completeness,
    check_correctness,
    check_projection_soundness,
)
from dbas_et.dvas.pam import commit, open_for_reason, verify_opening
from dbas_et.dvas.pam_api import Commit, Open, Select, Setup, Verify
from dbas_et.dvas.predicates import PREDICATES, required_fields
from dbas_et.dvas.schema import LAYOUT_V1
from dbas_et.dvas.workload import acn_sessions, mfev_sessions


@pytest.fixture(scope="module")
def contexts():
    return build_contexts(acn_sessions(max_rows=4) + mfev_sessions(max_rows=2))


def _assert_rows(rows):
    bad = [r for r in rows if not r["holds"]]
    assert not bad, bad


def test_api_is_a_wrapper_with_identical_behaviour(contexts):
    pp = Setup(LAYOUT_V1)
    assert pp.trusted_setup is False and pp.schema_digest == LAYOUT_V1.digest().hex()
    _, s, _ = contexts[0]
    rho, st = Commit(pp, s.commitment.values)
    assert rho == commit(s.commitment.values).rho_t == s.commitment.rho_t
    for r in PREDICATES:
        assert Select(pp, r) == required_fields(LAYOUT_V1, r)
        pi = Open(pp, st, Select(pp, r), r=r)
        assert pi == open_for_reason(st, r)
        assert Verify(pp, rho, r, pi) == verify_opening(rho, pi, reason=r)


def test_A_correctness(contexts):
    _assert_rows(check_correctness(contexts, random.Random(1), 3))


def test_B_opening_binding(contexts):
    _assert_rows(check_binding(contexts, random.Random(2), 25))


def test_C_predicate_completeness(contexts):
    _assert_rows(check_completeness(contexts, random.Random(3), 6))


def test_D_projection_soundness(contexts):
    _assert_rows(check_projection_soundness(contexts, random.Random(4), 8))


def test_verify_rejects_missing_or_malformed_required_field(contexts):
    pp = Setup(LAYOUT_V1)
    _, s, _ = contexts[0]
    pi = Open(pp, s.commitment, Select(pp, "settlement"), r="settlement")
    fields = dict(pi.fields)
    from dbas_et.dvas.schema import REGISTRY

    fields[REGISTRY.spec("cap_kwh").field_id] = "not-a-number"
    from dataclasses import replace

    assert Verify(pp, s.commitment.rho_t, "settlement", replace(pi, fields=tuple(sorted(fields.items())))).code == "ENCODING_ERROR"
