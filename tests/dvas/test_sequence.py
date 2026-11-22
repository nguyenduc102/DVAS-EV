"""Sequence/state attacks, top-up and replay at the ledger level."""

from __future__ import annotations

from decimal import Decimal

from dbas_et.dvas.ledger import TxState
from dbas_et.dvas.workload import ACN_TOPUP, acn_sessions

from ..conftest import ready


def _settled(env, spec):
    s = ready(env, spec, verify=True)
    s.aggregate()
    assert s.settle().ok
    return s


def test_settle_before_receipt(env, acn_specs):
    a = ready(env, acn_specs[0], verify=True)
    s = env.session(acn_specs[1]); s.commit(); s.authorize(); s.open_session()
    body = a.outcomes[0].body
    forged = type(body).build(**{**body.values, "settle_tid": s.spec.tid, "settle_sid": s.sid,
                                 "settle_rho_t": s.commitment.rho_t,
                                 "settle_meter_id": s.spec.meter_id})
    from .test_quorum import _att
    from dbas_et.dvas.rbc import QuorumRBC

    rbc = QuorumRBC(forged, (_att(env, "SV1", forged), _att(env, "SV2", forged)))
    assert env.ledger.settle(rbc).code == "RECEIPT_DIGEST_MISMATCH"
    assert env.ledger.records[s.spec.tid].state == TxState.DELIVERING


def test_settle_before_quorum(env, acn_specs):
    s = ready(env, acn_specs[2], verify=True)
    from dbas_et.dvas.rbc import QuorumRBC

    assert env.ledger.settle(QuorumRBC(s.outcomes[0].body, ())).code == "RBC_NO_ATTESTATIONS"
    assert env.ledger.settle(QuorumRBC(s.outcomes[0].body, (s.outcomes[0].attestation,))).code == "BELOW_THRESHOLD"


def test_duplicate_settlement_and_receipt_resubmission(env, acn_specs):
    s = _settled(env, acn_specs[3])
    assert env.ledger.settle(s.rbc).code == "RBC_REPLAY"
    assert env.ledger.submit_receipt(s.receipt).code == "REPLAY_AFTER_SETTLEMENT"


def test_topup_after_settled(env, acn_specs):
    s = _settled(env, acn_specs[4])
    assert s.topup(Decimal("1")).code == "TOPUP_NOT_ENABLED"


def test_cross_session_receipt_reuse(env, acn_specs):
    a = ready(env, acn_specs[5])
    b = env.session(acn_specs[6]); b.commit(); b.authorize(); b.open_session()
    assert env.ledger.submit_receipt(a.receipt.with_values(receipt_tid=b.spec.tid)).code in {
        "SID_MISMATCH", "RHO_MISMATCH", "METER_OR_STATION_MISMATCH", "BAD_METER_SIGNATURE"}


def test_cross_root_rbc_reuse(env, acn_specs):
    a = _settled(env, acn_specs[7])
    b = ready(env, acn_specs[8], verify=True)
    from dbas_et.dvas.rbc import QuorumRBC

    # A's (already used) RBC presented for B
    assert not env.ledger.settle(QuorumRBC(a.rbc.body, a.rbc.attestations)).ok
    assert env.ledger.records[b.spec.tid].state == TxState.RECEIPT_SUBMITTED


def test_sid_reuse_and_auth_request_replay(env, acn_specs):
    a = ready(env, acn_specs[9])
    b = env.session(acn_specs[10]); b.commit(); b.authorize()
    assert b.open_session(sid=a.sid).code == "SID_REUSED"
    assert b.authorize().code == "DUPLICATE_TID"


def test_topup_flow_keeps_root_and_settles():
    from dbas_et.dvas.profiles import PROFILES
    from dbas_et.dvas.protocol import DvasEnvironment

    env = DvasEnvironment(profile=PROFILES["C0"])
    specs = acn_sessions(ACN_TOPUP, max_rows=10)
    for sp in specs:
        s = ready(env, sp)
        rho = env.ledger.records[sp.tid].rho_t
        assert s.topup().ok
        assert env.ledger.records[sp.tid].rho_t == rho
        s.verify(); s.aggregate()
        r = s.settle()
        assert r.ok and r.value["captured"] == sp.expected_amount


def test_topup_validation(env, acn_specs):
    s = ready(env, acn_specs[11])
    rec = env.ledger.records[s.spec.tid]
    from dbas_et.dvas.ledger import topup_message
    from dbas_et.dvas.schema import PROTOCOL_VERSION_VALUE

    base = {"protocol_version": PROTOCOL_VERSION_VALUE, "tid": rec.tid, "rho_t": rec.rho_t, "sid": s.sid,
            "user_account": rec.user_account, "old_limit": rec.effective_limit, "delta_limit": Decimal("1"),
            "new_limit": rec.effective_limit + Decimal("2"), "event_nonce": "x1"}
    assert env.ledger.topup(base, s.user.signer.sign(topup_message(base))).code == "TOPUP_ARITHMETIC"
    v2 = {**base, "old_limit": rec.effective_limit + 1, "new_limit": rec.effective_limit + 2, "event_nonce": "x2"}
    assert env.ledger.topup(v2, s.user.signer.sign(topup_message(v2))).code == "TOPUP_OLD_LIMIT_MISMATCH"
    v3 = {**base, "new_limit": rec.effective_limit + 1, "event_nonce": "x3"}
    other = env.users[next(u for u in env.users if u != s.spec.user_id)] if len(env.users) > 1 else None
    if other:
        assert env.ledger.topup(v3, other.signer.sign(topup_message(v3))).code == "TOPUP_SIGNATURE_INVALID"
    assert env.ledger.topup(v3, s.user.signer.sign(topup_message(v3))).ok
    assert env.ledger.topup(v3, s.user.signer.sign(topup_message(v3))).code == "TOPUP_REPLAY"


def test_topup_between_attestation_and_settlement_invalidates_rbc(env, acn_specs):
    s = ready(env, acn_specs[12], verify=True)
    rbc = s.aggregate()
    assert s.topup(Decimal("1")).ok
    assert env.ledger.settle(rbc).code in {"REFUND_MISMATCH", "AUTH_STATE_CHANGED"}


def test_balances_conserved(env, acn_specs):
    total_before = sum(env.ledger.balances.values()) if env.ledger.balances else Decimal(0)
    for sp in acn_specs[13:18]:
        env.register_spec(sp)
    total_before = sum(env.ledger.balances.values())
    for sp in acn_specs[13:18]:
        _settled(env, sp)
    total_after = sum(env.ledger.balances.values()) + sum(env.ledger.payouts.values())
    assert total_after == total_before


def test_zero_headroom_boundary_row_is_amount_safe():
    """ACN original-cap row 2320: exact amount 0.52775855 -> 0.527759 > hold 0.527758.
    The legacy float path (MONEY_EPS=1e-5) captures 0.527759; DVAS-EV refuses (capture <= hold)."""
    from dbas_et.dvas.profiles import PROFILES
    from dbas_et.dvas.protocol import DvasEnvironment
    from dbas_et.dvas.workload import ACN_ORIGINAL_CAP

    spec = acn_sessions(ACN_ORIGINAL_CAP, max_rows=2321)[2320]
    assert spec.preauth_limit == Decimal("0.527758")
    r = DvasEnvironment(profile=PROFILES["C0"]).run(spec)
    assert not r.ok and "amount_within_effective_limit" in r.code
