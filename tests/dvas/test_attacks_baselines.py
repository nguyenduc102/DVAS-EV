"""Smoke tests for the attack library and the controlled baselines."""

from __future__ import annotations

import random

import pytest

from dbas_et.dvas.attacks import ATTACKS, RANDOMIZABLE, run_attack
from dbas_et.dvas.baselines import ATTACKS as BL_ATTACKS, BASELINES, detects, eligible
from dbas_et.dvas.profiles import PROFILES
from dbas_et.dvas.protocol import DvasEnvironment


@pytest.fixture(scope="module")
def attack_env():
    return DvasEnvironment(profile=PROFILES["C3"])


@pytest.mark.parametrize("name", sorted(ATTACKS))
def test_every_attack_rejected(attack_env, acn_specs, name):
    rng = random.Random(1) if name in RANDOMIZABLE else None
    r = run_attack(attack_env, name, acn_specs[3], acn_specs, generation="systematic", rng=rng)
    assert r.actual == "REJECTED", r


def test_randomized_cases_seeded_selection_only(acn_specs):
    """Same seed -> same attack parameters, even though keys are fresh."""
    def params(seed):
        env = DvasEnvironment(profile=PROFILES["C0"])
        rng = random.Random(seed)
        return [run_attack(env, "missing_required_field", acn_specs[i], acn_specs, generation="randomized",
                           rng=rng, case_no=i).params for i in range(5)]
    assert params(7) == params(7)


@pytest.mark.parametrize("name", list(BASELINES))
def test_baseline_honest_lifecycle(acn_specs, name):
    spec = next(s for s in acn_specs if eligible(s))
    run = BASELINES[name]().run(spec)
    assert run.ok and run.captured == spec.expected_amount
    assert set(run.phases) == {"authorize", "submit_receipt", "verify_delivery", "settle"}


def test_baseline_detection_matrix(acn_specs):
    spec = next(s for s in acn_specs if eligible(s))
    m = {(n, a): detects(cls(), spec, a)[0] for n, cls in BASELINES.items() for a in BL_ATTACKS}
    assert all(m[("DVAS-EV", a)] for a in BL_ATTACKS)
    assert all(m[("FullEscrow", a)] for a in BL_ATTACKS)
    assert not m[("HashAnchor", "post_authorization_tariff_swap")]
    assert not m[("CDR", "over_cap_delivery")]
