"""Predicate-complete PAM-Proof (completeness + Merkle authenticity)."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

import pytest

from dbas_et.dvas.canonical import EncodingError
from dbas_et.dvas.pam import (
    CompletenessPolicy,
    PAMOpening,
    ProofKind,
    commit,
    open_fields,
    open_for_reason,
    verify_opening,
)
from dbas_et.dvas.predicates import required_fields
from dbas_et.dvas.schema import LAYOUT_V1, REGISTRY

from .test_canonical import sample_layout

KINDS = [ProofKind.MULTIPROOF, ProofKind.INDEPENDENT]
REASONS = ["settlement", "authorization", "delivery_cap", "pricing", "dispute:over_cap", "replay"]


@pytest.fixture(scope="module")
def com():
    return commit(sample_layout())


def _fid(name: str) -> int:
    return REGISTRY.spec(name).field_id


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("reason", REASONS)
def test_8_valid_complete_opening(com, kind, reason):
    op = open_for_reason(com, reason, proof_kind=kind)
    assert verify_opening(com.rho_t, op, reason=reason).code == "OK"
    assert verify_opening(com.rho_t, op, reason=reason, policy=CompletenessPolicy.EXACT).code == "OK"
    rt = PAMOpening.from_bytes(op.to_bytes())
    assert verify_opening(com.rho_t, rt, reason=reason).code == "OK"


@pytest.mark.parametrize("kind", KINDS)
def test_1_omit_required_field_with_valid_merkle_proof(com, kind):
    req = required_fields(LAYOUT_V1, "settlement")
    for omitted in req:
        op = open_fields(com, [n for n in req if n != omitted], reason="settlement", proof_kind=kind)
        assert verify_opening(com.rho_t, op, reason="settlement", check_completeness=False).code == "OK"
        r = verify_opening(com.rho_t, op, reason="settlement")
        assert r.code == "INCOMPLETE_OPENING" and r.missing == (omitted,)


@pytest.mark.parametrize("kind", KINDS)
def test_2_replace_required_with_irrelevant_valid_field(com, kind):
    req = list(required_fields(LAYOUT_V1, "settlement"))
    fields = [n for n in req if n != "cap_kwh"] + ["requested_kwh"]  # authentic but irrelevant
    op = open_fields(com, fields, reason="settlement", proof_kind=kind)
    assert verify_opening(com.rho_t, op, reason="settlement", check_completeness=False).code == "OK"
    assert verify_opening(com.rho_t, op, reason="settlement").code == "INCOMPLETE_OPENING"


@pytest.mark.parametrize("kind", KINDS)
def test_3_correct_value_under_wrong_field_identifier(com, kind):
    op = open_for_reason(com, "settlement", proof_kind=kind)
    vals = dict(op.fields)
    s, m = _fid("station_id"), _fid("meter_id")
    vals[s], vals[m] = vals[m], vals[s]  # authentic values, swapped identifiers
    bad = replace(op, fields=tuple(sorted(vals.items())))
    assert verify_opening(com.rho_t, bad, reason="settlement").code == "ROOT_MISMATCH"
    # same value moved to an identifier of a different type fails encoding
    vals2 = dict(op.fields)
    vals2[_fid("tw_start")] = vals2[_fid("tid")]
    bad2 = replace(op, fields=tuple(sorted(vals2.items())))
    assert verify_opening(com.rho_t, bad2, reason="settlement").code == "ENCODING_ERROR"


@pytest.mark.parametrize("kind", KINDS)
def test_4_valid_multiproof_for_incomplete_predicate(com, kind):
    """A genuine proof generated for the delivery_cap subset is not accepted for settlement."""
    op = open_for_reason(com, "delivery_cap", proof_kind=kind)
    op = replace(op, reason="settlement")
    assert verify_opening(com.rho_t, op, reason="settlement", check_completeness=False).code == "OK"
    assert verify_opening(com.rho_t, op, reason="settlement").code == "INCOMPLETE_OPENING"


def test_4b_reason_relabel_rejected(com):
    op = open_for_reason(com, "delivery_cap")
    assert verify_opening(com.rho_t, op, reason="settlement").code == "REASON_MISMATCH"


@pytest.mark.parametrize("kind", KINDS)
def test_5_fields_from_wrong_phase(com, kind):
    op = open_for_reason(com, "settlement", proof_kind=kind)
    post = (_fid("delivered_kwh"), Decimal("1.0"))
    bad = replace(op, fields=tuple(sorted(op.fields + (post,))))
    assert verify_opening(com.rho_t, bad, reason="settlement").code == "WRONG_PHASE_FIELD"
    out = (_fid("captured_amount"), Decimal("1.0"))
    bad = replace(op, fields=tuple(sorted(op.fields + (out,))))
    assert verify_opening(com.rho_t, bad, reason="settlement").code == "WRONG_PHASE_FIELD"


@pytest.mark.parametrize("kind", KINDS)
def test_6_wrong_transaction_root(com, kind):
    other = commit({**sample_layout(), "tid": "another-transaction"})
    op = open_for_reason(com, "settlement", proof_kind=kind)
    assert verify_opening(other.rho_t, op, reason="settlement").code == "ROOT_MISMATCH"


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("field,new", [("cap_kwh", Decimal("999")), ("unit_price", Decimal("0.01")),
                                       ("tw_end", 1999999999), ("meter_id", "M_ATTACK")])
def test_7_tampered_value(com, kind, field, new):
    op = open_for_reason(com, "settlement", proof_kind=kind)
    vals = dict(op.fields)
    vals[_fid(field)] = new
    bad = replace(op, fields=tuple(sorted(vals.items())))
    assert verify_opening(com.rho_t, bad, reason="settlement").code == "ROOT_MISMATCH"


@pytest.mark.parametrize("kind", KINDS)
def test_9_complete_with_optional_extra_fields(com, kind):
    op = open_for_reason(com, "settlement", proof_kind=kind, extra_fields=["requested_kwh", "created_at"])
    assert verify_opening(com.rho_t, op, reason="settlement", policy=CompletenessPolicy.SUPERSET).code == "OK"
    r = verify_opening(com.rho_t, op, reason="settlement", policy=CompletenessPolicy.EXACT)
    assert r.code == "NON_EXACT_OPENING"


def test_structural_rejections(com):
    op = open_for_reason(com, "settlement")
    dup = replace(op, fields=op.fields + (op.fields[-1],))
    assert verify_opening(com.rho_t, dup, reason="settlement").code in {"DUPLICATE_FIELD", "NON_CANONICAL_ORDER"}
    unknown = replace(op, fields=op.fields + ((0x7FFF, "x"),))
    assert verify_opening(com.rho_t, unknown, reason="settlement").code == "UNKNOWN_FIELD"
    rev = replace(op, fields=tuple(reversed(op.fields)))
    assert verify_opening(com.rho_t, rev, reason="settlement").code == "NON_CANONICAL_ORDER"
    short = replace(op, helpers=op.helpers[:-1])
    assert verify_opening(com.rho_t, short, reason="settlement").code == "MALFORMED_PROOF"
    wrong_helper = replace(op, helpers=(b"\x00" * 32,) + op.helpers[1:])
    assert verify_opening(com.rho_t, wrong_helper, reason="settlement").code == "ROOT_MISMATCH"
    ind = open_for_reason(com, "settlement", proof_kind=ProofKind.INDEPENDENT)
    mixed = replace(ind, paths=(ind.paths[1],) + ind.paths[1:])
    assert verify_opening(com.rho_t, mixed, reason="settlement").code == "ROOT_MISMATCH"
    assert verify_opening(com.rho_t, op, reason="no-such-reason").code == "REASON_MISMATCH"


def test_wire_decoding_rejects_garbage(com):
    b = open_for_reason(com, "settlement").to_bytes()
    with pytest.raises(EncodingError):
        PAMOpening.from_bytes(b + b"\x01")
    with pytest.raises(EncodingError):
        PAMOpening.from_bytes(b"XXXX" + b[4:])


def test_multiproof_is_smaller_than_independent_paths(com):
    m = open_for_reason(com, "settlement", proof_kind=ProofKind.MULTIPROOF)
    i = open_for_reason(com, "settlement", proof_kind=ProofKind.INDEPENDENT)
    assert m.sibling_hash_count < i.sibling_hash_count
    assert m.opened_value_bytes() == i.opened_value_bytes()
