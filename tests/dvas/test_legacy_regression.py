"""Legacy regression R1-R5: each weakness is shown on the unchanged legacy path and
must be rejected (or handled safely) by DVAS-EV."""

from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "dvas"))

import run_legacy_regression as rr  # noqa: E402

from dbas_et.dvas.attacks import unique  # noqa: E402
from dbas_et.dvas.tariff import tariff_amount  # noqa: E402
from dbas_et.dvas.workload import ACN_VALID, acn_sessions, honest_amount  # noqa: E402


@pytest.fixture(scope="module")
def spec(acn_specs):
    return unique(acn_specs[0], "legacy-test")


@pytest.mark.parametrize("issue", ["r1", "r2", "r3"])
def test_r1_r3(spec, issue):
    legacy, new, ok = getattr(rr, issue)(unique(spec, issue))
    assert legacy.startswith("ACCEPTED"), legacy  # weakness present in the legacy code
    assert ok, new


def test_r4_float_tolerance_over_capture():
    legacy, new, ok = rr.r4()
    assert legacy.startswith("ACCEPTED") and ok, (legacy, new)


def test_r5_no_default_operand():
    legacy, new, ok = rr.r5()
    assert legacy.startswith("ACCEPTED") and ok, (legacy, new)


def test_dataset_expected_amount_rounding_is_documented():
    """The dataset column was float-rounded; exactly the documented half-way rows differ by 1e-6."""
    diffs = [s.row_index for s in acn_sessions(ACN_VALID) if s.expected_amount != honest_amount(s)]
    assert len(diffs) == 4 and {491, 2320, 2648} <= set(diffs)
    for s in acn_sessions(ACN_VALID, max_rows=3000):
        assert abs(s.expected_amount - honest_amount(s)) <= Decimal("0.000001")
        assert honest_amount(s) == tariff_amount(mode=s.tariff_mode, unit_price=s.unit_price,
                                                 delivered_kwh=s.delivered_kwh,
                                                 connection_duration_s=s.connection_duration_s,
                                                 active_charging_duration_s=s.active_charging_duration_s,
                                                 parking_duration_s=s.parking_duration_s)
