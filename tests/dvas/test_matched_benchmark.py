"""Semantic and process-isolation checks. These are not performance samples."""
import os
from decimal import Decimal

import pytest

from dbas_et.dvas import benchmark_wire as wire
from dbas_et.dvas.attacks import unique
from dbas_et.dvas.delivery import h_priv_of, private_payload_bytes
from dbas_et.dvas.matched_benchmark import METHODS, WorkerCluster, public_delivery, run_session
from dbas_et.dvas.profiles import PROFILES, verify_signature
from dbas_et.dvas.protocol import DvasEnvironment
from dbas_et.dvas.workload import acn_sessions, honest_amount


@pytest.fixture
def spec():
    return next(s for s in acn_sessions(max_rows=100)
                if not s.expected_undercap and s.delivered_kwh <= s.cap_kwh
                and s.preauth_limit > honest_amount(s))


def setup(spec, profile="C0", n=3, t=2):
    env = DvasEnvironment(profile=PROFILES[profile], n=n, t=t)
    env.register_spec(spec)
    return env


def test_wire_registry_and_opening_roundtrip(spec):
    env = setup(spec)
    reg = wire.registry_load(wire.registry_dump(env.registry))
    assert wire.registry_dump(reg) == wire.registry_dump(env.registry)
    session = env.session(spec)
    session.commit()
    assert wire.loads(wire.dumps(session.auth_request())) == session.auth_request()
    assert wire.loads(wire.dumps({"decimal": Decimal("0.000001"), "blob": b"\x00\xff"})) == {
        "decimal": Decimal("0.000001"), "blob": b"\x00\xff"}
    with pytest.raises((ValueError, KeyError)):
        wire.loads(b'{"@record":"ArbitraryExecutable","fields":{}}')
    with pytest.raises(ValueError):
        wire.loads(b'{"@unknown":"bad"}')


def test_public_meter_payload_matches_production(spec):
    env = setup(spec)
    s = env.session(spec)
    s.commit(); assert s.authorize().ok; assert s.open_session().ok
    public, plaintext = public_delivery(s)
    s.deliver()
    assert plaintext == private_payload_bytes(s.private_values)
    assert public.encoded() == s.receipt.encoded()
    assert h_priv_of(plaintext) == public["h_priv"]
    assert verify_signature(s.meter.signer.scheme, s.meter.signer.public_key, public.message(), public.signature)
    assert wire.loads(wire.dumps(public)) == public
    assert wire.loads(wire.dumps(s.settlement_request())) == s.settlement_request()


@pytest.mark.parametrize("profile", ["C0", "C3"])
@pytest.mark.parametrize("method", METHODS)
def test_matched_honest_amount_and_replay(spec, profile, method):
    env = setup(spec, profile)
    cluster = WorkerCluster(env, profile) if method != METHODS[0] else None
    try:
        if cluster:
            assert len(cluster.pids) == 3 and os.getpid() not in cluster.pids
        r = run_session(env, spec, method, cluster, mutation="replay", scenario={"deadline_ms": 2000})
        assert r["ok"] and r["accounting_ok"] and r["replay_refused"]
        assert Decimal(r["captured"]) == honest_amount(spec)
        assert r["public_application_bytes"] > 0
        if cluster:
            assert r["responses"] >= 2 and r["private_application_bytes"] > 0
            assert set(map(int, r["responding_pids"].split(","))) <= set(cluster.pids)
            assert r["tcp_sent_bytes"] > 0 and r["tcp_received_bytes"] > 0
        else:
            assert r["private_application_bytes"] == 0
    finally:
        if cluster:
            cluster.close()


@pytest.mark.parametrize("method", METHODS)
def test_matched_security_semantics(spec, method):
    env = setup(spec, "C3")
    cluster = WorkerCluster(env, "C3") if method != METHODS[0] else None
    try:
        for mutation in ("tariff_swap", "over_cap", "private_substitution", "incomplete_opening"):
            sp = unique(spec, mutation)
            r = run_session(env, sp, method, cluster, mutation=mutation, scenario={"deadline_ms": 2000})
            assert not r["ok"], (mutation, r)
            assert r["ledger_state"] == "RECEIPT_SUBMITTED"
            rec = env.ledger.records[sp.tid]
            assert rec.captured == 0 and rec.refunded == 0 and rec.held == sp.preauth_limit
    finally:
        if cluster:
            cluster.close()


@pytest.mark.parametrize("n,t", [(3, 2), (5, 3)])
def test_real_offline_and_withholding_liveness(spec, n, t):
    env = setup(spec, n=n, t=t)
    cluster = WorkerCluster(env, "C0")
    ids = list(cluster.workers)
    try:
        r = run_session(env, unique(spec, "withhold-ok"), METHODS[2], cluster,
            scenario={"withholding": ids[:n-t], "deadline_ms": 2000})
        assert r["ok"] and r["responses"] >= t
        r = run_session(env, unique(spec, "withhold-fail"), METHODS[2], cluster,
            scenario={"withholding": ids[:n-t+1], "deadline_ms": 200})
        assert not r["ok"] and r["deadline_reached"]
        cluster.offline(ids[:n-t])
        assert len(cluster.pids) == t
        r = run_session(env, unique(spec, "offline-ok"), METHODS[2], cluster, scenario={"deadline_ms": 2000})
        assert r["ok"]
        cluster.offline([ids[n-t]])
        r = run_session(env, unique(spec, "offline-fail"), METHODS[2], cluster, scenario={"deadline_ms": 2000})
        assert not r["ok"] and r["responses"] < t
    finally:
        cluster.close()


def test_differing_decision_digests_and_safety_boundary(spec):
    env = setup(spec)
    cluster = WorkerCluster(env, "C0")
    try:
        r = run_session(env, unique(spec, "one-inflate"), METHODS[2], cluster,
                        scenario={"behaviors": {"SV1": "inflate"}, "deadline_ms": 2000})
        assert r["ok"] and Decimal(r["captured"]) == honest_amount(spec)
        r = run_session(env, unique(spec, "threshold-inflate"), METHODS[2], cluster,
            scenario={"behaviors": {"SV1": "inflate", "SV2": "inflate"}, "deadline_ms": 2000})
        assert r["ok"] and Decimal(r["captured"]) == spec.preauth_limit
        assert r["accounting_ok"] and Decimal(r["captured"]) != honest_amount(spec)
    finally:
        cluster.close()
