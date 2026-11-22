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

DATA = (ROOT / "data").resolve()


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    # Tests that read the ACN/MFEV workloads are reported as skipped on a clone
    # without data/ (see data/README.md). Any other missing file is still an error.
    rep = yield
    e = call.excinfo.value if call.excinfo else None
    if isinstance(e, FileNotFoundError) and str(DATA) in str(e.filename or e):
        rep.outcome = "skipped"
        rep.longrepr = (str(item.path), item.location[1], f"Skipped: dataset not found ({e})")
    return rep


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
