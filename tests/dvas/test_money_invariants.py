"""Exact money semantics: no floating-point tolerance can allow over-capture.

Invariants enforced by SettleSC for every accepted settlement:
    0 <= capture <= hold,  capture <= effective (authorized) limit,  refund == hold - capture.
"""

from __future__ import annotations

import inspect
import random
import re
from decimal import Decimal
from pathlib import Path

import pytest

from dbas_et.dvas import ledger as ledger_mod
from dbas_et.dvas.canonical import EncodingError
from dbas_et.dvas.rbc import QuorumRBC, RBCBody

from ..conftest import ready
from .test_quorum import _att

DVAS_DIR = Path(ledger_mod.__file__).parent


def test_no_money_epsilon_in_dvas():
    for p in DVAS_DIR.glob("*.py"):
        src = p.read_text()
        assert not re.search(r"\bMONEY_EPS\b|\bisclose\(|_TOLERANCE\b", src), p.name
    assert "float(" not in inspect.getsource(ledger_mod.DvasLedger.settle)


def _honest_body(env, spec):
    s = ready(env, spec, verify=True)
    return s, s.outcomes[0].body


def _settle(env, body):
    rbc = QuorumRBC(body, (_att(env, "SV1", body), _att(env, "SV2", body)))
    return env.ledger.settle(rbc)


@pytest.mark.parametrize("delta", ["0.000001", "0.0000005", "0.00001"])
def test_capture_one_micro_unit_over_hold_rejected(env, acn_specs, delta):
    """Even a full quorum signing hold + epsilon is refused; sub-micro values cannot be encoded at all."""
    s, b = _honest_body(env, acn_specs[0])
    hold = env.ledger.records[s.spec.tid].held
    cap = hold + Decimal(delta)
    try:
        forged = RBCBody.build(**{**b.values, "captured_amount": cap, "refund_amount": Decimal(0)})
    except EncodingError:
        assert Decimal(delta) * 10**6 % 1 != 0  # not representable at 6 decimals -> rejected at encoding
        return
    assert _settle(env, forged).code in {"CAPTURE_EXCEEDS_LIMIT", "CAPTURE_EXCEEDS_HOLD"}


def test_randomized_invariants_on_accepted_settlements(env, acn_specs):
    rng = random.Random(9)  # selects amounts only
    accepted = 0
    for spec in acn_specs[1:16]:
        s, b = _honest_body(env, spec)
        rec = env.ledger.records[s.spec.tid]
        hold, limit = rec.held, rec.effective_limit
        cap = (hold * Decimal(rng.uniform(-0.2, 1.2))).quantize(Decimal("0.000001"))
        ref = hold - cap if rng.random() < 0.8 else hold - cap + Decimal("0.000001")
        ref = max(ref, Decimal(0))
        forged = RBCBody.build(**{**b.values, "captured_amount": cap, "refund_amount": ref})
        r = _settle(env, forged)
        invariants = Decimal(0) <= cap <= hold and cap <= limit and ref == hold - cap
        assert r.ok == invariants, (cap, ref, hold, r.code)  # quorum-signed body accepted IFF invariants hold
        if r.ok:
            accepted += 1
            assert env.ledger.records[s.spec.tid].held == 0
    assert accepted >= 1


def test_legacy_over_hold_row_stays_refused():
    """ACN original-cap row 2320 (legacy captured hold + 1e-6 through MONEY_EPS)."""
    from dbas_et.dvas.profiles import PROFILES
    from dbas_et.dvas.protocol import DvasEnvironment
    from dbas_et.dvas.workload import ACN_ORIGINAL_CAP, acn_sessions

    spec = acn_sessions(ACN_ORIGINAL_CAP, max_rows=2321)[2320]
    r = DvasEnvironment(profile=PROFILES["C0"]).run(spec)
    assert not r.ok and "amount_within_effective_limit" in r.code


def test_float_inputs_cannot_smuggle_rounding(env, acn_specs):
    s, b = _honest_body(env, acn_specs[17])
    with pytest.raises(EncodingError):
        RBCBody.build(**{**b.values, "captured_amount": 0.1 + 0.2})  # 0.30000000000000004
