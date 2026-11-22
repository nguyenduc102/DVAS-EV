from __future__ import annotations

import sys
import warnings
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.filterwarnings("ignore", message=".*liboqs version.*")

from dbas_et.dvas.profiles import PROFILES  # noqa: E402
from dbas_et.dvas.protocol import DvasEnvironment, Session  # noqa: E402
from dbas_et.dvas.workload import acn_sessions  # noqa: E402


@pytest.fixture(scope="session")
def acn_specs():
    return acn_sessions(max_rows=40)


@pytest.fixture
def env():
    return DvasEnvironment(profile=PROFILES["C0"])


@pytest.fixture
def env_c3():
    return DvasEnvironment(profile=PROFILES["C3"])


def ready(env: DvasEnvironment, spec, *, verify: bool = False) -> Session:
    """Run a session up to RECEIPT_SUBMITTED (optionally through verification)."""
    s = env.session(spec)
    s.commit()
    assert s.authorize().ok
    assert s.open_session().ok
    s.deliver()
    assert s.submit_receipt().ok
    if verify:
        s.verify()
    return s
