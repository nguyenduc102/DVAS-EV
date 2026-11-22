"""
Contract-state simulation for DVAS-EV (AuthSC + SettleSC with quorum RBC).

Money is Decimal with 6 decimals throughout (no float tolerance).

SettleSC.settle(rbc) checks, in order:
  1. RBC structure (version, decision, policy, non-empty attestations);
  2. tid/sid/rho_t binding to the authorization/session record;
  3. receipt digest and h_priv equal the submitted meter receipt;
  4. amount bounds: 0 <= capture <= effective limit, capture <= hold,
     refund == hold - capture, and auth_digest equals current record state;
  5. distinct verifier identities (duplicates reject the whole RBC);
  6. registered, active, non-revoked VERIFIER keys at the attested epoch,
     and the body's verifier-set epoch equals the current one;
  7. every attestation carries the body's decision digest;
  8. every signature verifies; the number of valid attestations >= t;
  9. replay state (receipt digest and RBC digest unused) -- evaluated
     right after (1) so a replay is reported as such;
 10. transaction state == RECEIPT_SUBMITTED;
 11. atomic consumption: mark receipt + RBC used, transfer, state SETTLED.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from typing import Any, Mapping

from .canonical import EncodingError, encode_record, normalize_value, tagged_hash, to_fixed6
from .delivery import PublicReceipt
from .instrumentation import count
from .pam import CompletenessPolicy, PAMOpening, verify_opening
from .predicates import evaluate, predicate_for
from .profiles import verify_signature
from .rbc import RBC_VERSION, SETTLEMENT_POLICY_ID, QuorumRBC, attestation_message
from .registry import KeyRegistry, Role
from .schema import AUTH_REQUEST, PROTOCOL_VERSION_VALUE, REGISTRY, SESSION_OPEN, TOPUP_EVENT


class TxState(str, Enum):
    AUTHORIZED = "AUTHORIZED"
    DELIVERING = "DELIVERING"
    RECEIPT_SUBMITTED = "RECEIPT_SUBMITTED"
    SETTLED = "SETTLED"


@dataclass(frozen=True)
class LedgerResult:
    ok: bool
    code: str
    detail: str = ""
    value: Any = None


def _ok(value: Any = None, code: str = "OK") -> LedgerResult:
    return LedgerResult(True, code, "", value)


def _rej(code: str, detail: str = "") -> LedgerResult:
    return LedgerResult(False, code, detail)


@dataclass
class AuthRecord:
    tid: str
    rho_t: str
    user_id: str
    user_account: str
    station_id: str
    meter_id: str
    beneficiary: str
    paytok: str
    currency: str
    initial_limit: Decimal
    effective_limit: Decimal
    held: Decimal
    state: TxState = TxState.AUTHORIZED
    sid: str = ""
    receipt_digest: str = ""
    h_priv: str = ""
    captured: Decimal = Decimal(0)
    refunded: Decimal = Decimal(0)
    topup_count: int = 0


@dataclass(frozen=True)
class QuorumPolicy:
    n: int
    t: int
    allow_minority_threshold: bool = False

    def __post_init__(self) -> None:
        if not (1 <= self.t <= self.n):
            raise ValueError("require 1 <= t <= n")
        if not self.allow_minority_threshold and self.t <= self.n // 2:
            raise ValueError("t must exceed n/2 so that two conflicting quorums cannot both form")


def _msg(rtype: Any, values: Mapping[str, Any]) -> bytes:
    return tagged_hash(f"DVAS-EV/{rtype.name}-sig/v1", encode_record(REGISTRY, rtype, values))


def auth_request_message(values: Mapping[str, Any]) -> bytes:
    return _msg(AUTH_REQUEST, values)


def session_open_message(values: Mapping[str, Any]) -> bytes:
    return _msg(SESSION_OPEN, values)


def topup_message(values: Mapping[str, Any]) -> bytes:
    return _msg(TOPUP_EVENT, values)


@dataclass
class DvasLedger:
    registry: KeyRegistry
    policy: QuorumPolicy
    completeness_policy: CompletenessPolicy = CompletenessPolicy.SUPERSET
    balances: dict[str, Decimal] = field(default_factory=dict)
    payouts: dict[str, Decimal] = field(default_factory=dict)
    records: dict[str, AuthRecord] = field(default_factory=dict)
    used_receipts: set[str] = field(default_factory=set)
    used_rbc: set[str] = field(default_factory=set)
    used_sids: set[str] = field(default_factory=set)
    used_event_nonces: set[str] = field(default_factory=set)

    def _transition(self, rec: AuthRecord, new: TxState) -> None:
        count("state_transition")
        rec.state = new

    def deposit(self, account: str, amount: Any) -> None:
        self.balances[account] = self.balances.get(account, Decimal(0)) + to_fixed6(amount)

    def auth_digest(self, tid: str) -> str:
        r = self.records[tid]
        parts = [r.tid, r.rho_t, r.user_account, r.station_id, r.meter_id, r.sid, str(r.effective_limit),
                 str(r.held), str(r.topup_count), r.state.value]
        return tagged_hash("DVAS-EV/auth-record/v1", *(p.encode() for p in parts)).hex()

    def session_is_open(self, tid: str, sid: str) -> bool:
        r = self.records.get(tid)
        return bool(r and r.sid == sid and r.state == TxState.RECEIPT_SUBMITTED)

    # ------------------------------------------------------------------ authorize
    def authorize(self, request: Mapping[str, Any], signature: bytes, opening: PAMOpening) -> LedgerResult:
        try:
            req = {k: normalize_value(REGISTRY.spec(k), v) for k, v in request.items()}
            msg = auth_request_message(req)
        except EncodingError as exc:
            return _rej("MALFORMED_REQUEST", str(exc))
        tid = req["tid"]
        if tid in self.records:
            return _rej("DUPLICATE_TID")
        if req["event_nonce"] in self.used_event_nonces:
            return _rej("REPLAYED_REQUEST")
        lk = self.registry.lookup(req["user_id"], Role.USER)
        if not lk.ok:
            return _rej(f"USER_KEY_{lk.reason}")
        if not verify_signature(lk.record.key_type, lk.record.public_key, msg, signature):  # type: ignore[union-attr]
            return _rej("BAD_USER_SIGNATURE")
        pv = verify_opening(req["rho_t"], opening, reason="authorization", policy=self.completeness_policy)
        if not pv.ok:
            return _rej(f"PAM_{pv.code}", pv.detail)
        v = pv.values
        balance = self.balances.get(req["user_account"], Decimal(0))
        evidence = {
            "request_tid": tid, "request_user_id": req["user_id"], "request_user_account": req["user_account"],
            "request_paytok": req["paytok"], "available_balance": balance,
        }
        count("bound_check")
        res = evaluate(predicate_for("authorization"), v, evidence, self.registry.relations())
        if not res.ok:
            return _rej("AUTHORIZATION_PREDICATE_FAILED", res.reason)
        if v["preauth_limit"] != req["preauth_limit"]:
            return _rej("LIMIT_MISMATCH")
        limit = v["preauth_limit"]
        self.balances[req["user_account"]] = balance - limit
        self.used_event_nonces.add(req["event_nonce"])
        rec = AuthRecord(tid, req["rho_t"], v["user_id"], v["user_account"], v["station_id"], v["meter_id"],
                         v["beneficiary"], v["paytok"], v["currency"], limit, limit, limit)
        self.records[tid] = rec
        count("state_transition")
        count("retained_object")
        return _ok(rec)

    # ------------------------------------------------------------------ session
    def open_session(self, values: Mapping[str, Any], signature: bytes) -> LedgerResult:
        try:
            vals = {k: normalize_value(REGISTRY.spec(k), v) for k, v in values.items()}
            msg = session_open_message(vals)
        except EncodingError as exc:
            return _rej("MALFORMED_SESSION", str(exc))
        rec = self.records.get(vals["tid"])
        if rec is None:
            return _rej("UNKNOWN_TID")
        if rec.state != TxState.AUTHORIZED:
            return _rej("BAD_STATE", rec.state.value)
        if vals["rho_t"] != rec.rho_t or vals["station_id"] != rec.station_id or vals["meter_id"] != rec.meter_id:
            return _rej("SESSION_BINDING_MISMATCH")
        if vals["sid"] in self.used_sids:
            return _rej("SID_REUSED")
        lk = self.registry.lookup(rec.station_id, Role.STATION)
        if not lk.ok:
            return _rej(f"STATION_KEY_{lk.reason}")
        if not verify_signature(lk.record.key_type, lk.record.public_key, msg, signature):  # type: ignore[union-attr]
            return _rej("BAD_STATION_SIGNATURE")
        rec.sid = vals["sid"]
        self.used_sids.add(vals["sid"])
        self._transition(rec, TxState.DELIVERING)
        return _ok(rec)

    # ------------------------------------------------------------------ receipt
    def submit_receipt(self, receipt: PublicReceipt) -> LedgerResult:
        tid = receipt["receipt_tid"]
        rec = self.records.get(tid)
        if rec is None:
            return _rej("UNKNOWN_TID")
        if rec.state == TxState.SETTLED:
            return _rej("REPLAY_AFTER_SETTLEMENT")
        if rec.state != TxState.DELIVERING:
            return _rej("BAD_STATE", rec.state.value)
        if receipt["sid"] != rec.sid:
            return _rej("SID_MISMATCH")
        if receipt["rho_t"] != rec.rho_t:
            return _rej("RHO_MISMATCH")
        if receipt["receipt_meter_id"] != rec.meter_id or receipt["receipt_station_id"] != rec.station_id:
            return _rej("METER_OR_STATION_MISMATCH")
        if self.registry.meter_station.get(rec.meter_id) != rec.station_id:
            return _rej("METER_NOT_BOUND_TO_STATION")
        lk = self.registry.lookup(rec.meter_id, Role.METER, epoch=receipt["meter_key_epoch"])
        if not lk.ok:
            return _rej(f"METER_KEY_{lk.reason}")
        if not verify_signature(lk.record.key_type, lk.record.public_key, receipt.message(), receipt.signature):  # type: ignore[union-attr]
            return _rej("BAD_METER_SIGNATURE")
        d = receipt.dr_digest
        if d in self.used_receipts:
            return _rej("RECEIPT_REPLAY")
        rec.receipt_digest = d
        rec.h_priv = receipt["h_priv"]
        self._transition(rec, TxState.RECEIPT_SUBMITTED)
        count("retained_object")
        return _ok(rec)

    # ------------------------------------------------------------------ top-up
    def topup(self, values: Mapping[str, Any], signature: bytes) -> LedgerResult:
        try:
            vals = {k: normalize_value(REGISTRY.spec(k), v) for k, v in values.items()}
            msg = topup_message(vals)
        except EncodingError as exc:
            return _rej("MALFORMED_TOPUP", str(exc))
        rec = self.records.get(vals["tid"])
        if rec is None:
            return _rej("UNKNOWN_TID")
        if rec.state not in (TxState.AUTHORIZED, TxState.DELIVERING, TxState.RECEIPT_SUBMITTED):
            return _rej("TOPUP_NOT_ENABLED", rec.state.value)
        if vals["rho_t"] != rec.rho_t or vals["user_account"] != rec.user_account:
            return _rej("TOPUP_BINDING_MISMATCH")
        if vals["event_nonce"] in self.used_event_nonces:
            return _rej("TOPUP_REPLAY")
        lk = self.registry.lookup(rec.user_id, Role.USER)
        if not lk.ok:
            return _rej(f"USER_KEY_{lk.reason}")
        if not verify_signature(lk.record.key_type, lk.record.public_key, msg, signature):  # type: ignore[union-attr]
            return _rej("TOPUP_SIGNATURE_INVALID")
        count("bound_check")
        if vals["delta_limit"] <= 0 or vals["new_limit"] != vals["old_limit"] + vals["delta_limit"]:
            return _rej("TOPUP_ARITHMETIC")
        if vals["old_limit"] != rec.effective_limit:
            return _rej("TOPUP_OLD_LIMIT_MISMATCH")
        bal = self.balances.get(rec.user_account, Decimal(0))
        if bal < vals["delta_limit"]:
            return _rej("INSUFFICIENT_BALANCE_FOR_TOPUP")
        self.balances[rec.user_account] = bal - vals["delta_limit"]
        rec.effective_limit = vals["new_limit"]
        rec.held += vals["delta_limit"]
        rec.topup_count += 1
        self.used_event_nonces.add(vals["event_nonce"])
        count("state_transition")
        return _ok(rec)

    # ------------------------------------------------------------------ settle
    def settle(self, rbc: QuorumRBC) -> LedgerResult:
        b = rbc.body
        try:
            body_digest = b.digest
        except EncodingError as exc:
            return _rej("RBC_MALFORMED", str(exc))
        # 1. structure
        if b["rbc_version"] != RBC_VERSION or b["settle_protocol_version"] != PROTOCOL_VERSION_VALUE:
            return _rej("RBC_VERSION")
        if b["decision"] != "ACCEPT":
            return _rej("RBC_NOT_ACCEPT")
        if b["policy_id"] != SETTLEMENT_POLICY_ID:
            return _rej("RBC_POLICY_MISMATCH")
        if not rbc.attestations:
            return _rej("RBC_NO_ATTESTATIONS")
        rec = self.records.get(b["settle_tid"])
        if rec is None:
            return _rej("UNKNOWN_TID")
        # 9. replay (evaluated early so that replays get a precise reason)
        if body_digest in self.used_rbc:
            return _rej("RBC_REPLAY")
        if b["dr_digest"] in self.used_receipts:
            return _rej("RECEIPT_REPLAY")
        # 2. tid/sid/rho binding
        if b["settle_sid"] != rec.sid:
            return _rej("WRONG_SESSION")
        if b["settle_rho_t"] != rec.rho_t:
            return _rej("WRONG_ROOT")
        if b["settle_meter_id"] != rec.meter_id:
            return _rej("WRONG_METER")
        # 3. receipt digest
        if not rec.receipt_digest or b["dr_digest"] != rec.receipt_digest or b["settle_h_priv"] != rec.h_priv:
            return _rej("RECEIPT_DIGEST_MISMATCH")
        # 4. amount bounds and authorization state digest
        count("bound_check", 4)
        cap, ref = b["captured_amount"], b["refund_amount"]
        if cap < 0 or cap > rec.effective_limit:
            return _rej("CAPTURE_EXCEEDS_LIMIT")
        if cap > rec.held:
            return _rej("CAPTURE_EXCEEDS_HOLD")
        if ref != rec.held - cap:
            return _rej("REFUND_MISMATCH")
        if b["auth_digest"] != self.auth_digest(rec.tid):
            return _rej("AUTH_STATE_CHANGED")
        # 5. distinct verifier identities
        ids = [a.verifier_id for a in rbc.attestations]
        if len(set(ids)) != len(ids):
            return _rej("DUPLICATE_VERIFIER")
        if b["verifier_set_epoch"] != self.registry.verifier_set_epoch:
            return _rej("STALE_VERIFIER_SET")
        valid = 0
        for a in rbc.attestations:
            # 6. key validity
            lk = self.registry.lookup(a.verifier_id, Role.VERIFIER, epoch=a.verifier_key_epoch)
            if not lk.ok:
                return _rej(f"VERIFIER_KEY_{lk.reason}", a.verifier_id)
            # 7. identical decision digest
            if a.decision_digest != body_digest or a.tid != b["settle_tid"] or a.decision != "ACCEPT":
                return _rej("DECISION_DIGEST_MISMATCH", a.verifier_id)
            # 8. signature
            msg = attestation_message(a.verifier_id, a.verifier_key_epoch, body_digest)
            if not verify_signature(lk.record.key_type, lk.record.public_key, msg, a.signature):  # type: ignore[union-attr]
                return _rej("BAD_VERIFIER_SIGNATURE", a.verifier_id)
            valid += 1
        if valid < self.policy.t:
            return _rej("BELOW_THRESHOLD", f"{valid} < {self.policy.t}")
        # 10. state
        if rec.state != TxState.RECEIPT_SUBMITTED:
            return _rej("BAD_STATE", rec.state.value)
        # 11. atomic consumption
        self.used_receipts.add(b["dr_digest"])
        self.used_rbc.add(body_digest)
        rec.captured, rec.refunded = cap, ref
        self.balances[rec.user_account] = self.balances.get(rec.user_account, Decimal(0)) + ref
        self.payouts[rec.beneficiary] = self.payouts.get(rec.beneficiary, Decimal(0)) + cap
        rec.held = Decimal(0)
        self._transition(rec, TxState.SETTLED)
        return _ok({"tid": rec.tid, "captured": cap, "refund": ref, "attestations": valid})

    # ------------------------------------------------------------------ dispute
    def dispute_check(self, tid: str, reason: str, opening: PAMOpening, evidence: Mapping[str, Any]) -> LedgerResult:
        """Reason-aware dispute opening: predicate-complete PAM verify + predicate evaluation."""
        rec = self.records.get(tid)
        if rec is None:
            return _rej("UNKNOWN_TID")
        pv = verify_opening(rec.rho_t, opening, reason=reason, policy=self.completeness_policy)
        if not pv.ok:
            return _rej(f"PAM_{pv.code}", pv.detail)
        relations = dict(self.registry.relations())
        relations["fresh_receipt"] = lambda d: d not in self.used_receipts
        relations["fresh_session"] = lambda t, s: self.session_is_open(t, s)
        res = evaluate(predicate_for(reason), pv.values, evidence, relations)
        return _ok({"predicate_holds": res.ok, "failed": res.failed, "missing": res.missing})
