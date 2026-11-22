"""
End-to-end DVAS-EV session orchestration.

    committed pre-service authorization        (commit + PAM "authorization")
      -> predicate-complete authenticated opening
      -> meter-authenticated public/private delivery binding
      -> independent verifier decisions
      -> t-of-n quorum RBC
      -> replay-safe, amount-safe settlement

``Session`` exposes each stage separately so attack generators can stop,
mutate and resume.  Timings are local protocol-processing latency
(time.perf_counter), not EV-charging end-to-end latency.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Iterable

from ..capsule import build_payment_token
from .delivery import MeterDevice, PublicReceipt
from .evidence import EvidenceEnvelope, RecipientKey
from .ledger import (
    DvasLedger,
    LedgerResult,
    QuorumPolicy,
    auth_request_message,
    session_open_message,
    topup_message,
)
from .pam import Commitment, CompletenessPolicy, PAMOpening, ProofKind, commit, open_for_reason
from .profiles import DEFAULT_PROFILE, CryptoProfile, KEMKeypair, Signer
from .rbc import QuorumRBC, RBCBody, aggregate
from .registry import KeyRegistry, Role
from .schema import LAYOUT_SCHEMA_ID, PROTOCOL_VERSION_VALUE
from .verifier import SettlementRequest, VerifierNode, VerifierOutcome
from .workload import SessionSpec


@dataclass
class UserAgent:
    user_id: str
    account: str
    home_operator: str
    signer: Signer


@dataclass
class StationAgent:
    station_id: str
    operator: str
    beneficiary: str
    signer: Signer


def account_of(signer: Signer) -> str:
    return "0x" + hashlib.sha256(signer.public_key).hexdigest()[:40]


class DvasEnvironment:
    """Registry + ledger + verifier cluster + registered parties."""

    def __init__(
        self,
        *,
        profile: CryptoProfile = DEFAULT_PROFILE,
        n: int = 3,
        t: int = 2,
        behaviors: dict[str, str] | None = None,
        completeness_policy: CompletenessPolicy = CompletenessPolicy.SUPERSET,
        proof_kind: ProofKind = ProofKind.MULTIPROOF,
        allow_minority_threshold: bool = False,
    ) -> None:
        self.profile = profile
        self.registry = KeyRegistry()
        self.ledger = DvasLedger(self.registry, QuorumPolicy(n, t, allow_minority_threshold), completeness_policy)
        self.proof_kind = proof_kind
        self.users: dict[str, UserAgent] = {}
        self.stations: dict[str, StationAgent] = {}
        self.meters: dict[str, MeterDevice] = {}
        self.verifiers: dict[str, VerifierNode] = {}
        behaviors = behaviors or {}
        for i in range(1, n + 1):
            vid = f"SV{i}"
            self.add_verifier(vid, operator=f"VERIFIER_OP_{i}", behavior=behaviors.get(vid, "honest"))

    # -- registration -----------------------------------------------------
    def add_verifier(self, vid: str, *, operator: str, behavior: str = "honest") -> VerifierNode:
        signer = Signer(self.profile.verifier_sig)
        kem = KEMKeypair(self.profile.kem)
        r1 = self.registry.register(vid, Role.VERIFIER, operator, signer.public_key, signer.scheme)
        r2 = self.registry.register(vid, Role.VERIFIER, operator, kem.public_key, kem.scheme, purpose="kem")
        node = VerifierNode(vid, operator, signer, kem, r1.key_epoch, r2.key_epoch, behavior,
                            self.ledger.completeness_policy)
        self.verifiers[vid] = node
        return node

    def add_user(self, user_id: str, home_operator: str, balance: Any = Decimal("1000000")) -> UserAgent:
        if user_id in self.users:
            return self.users[user_id]
        signer = Signer(self.profile.auth_sig)
        self.registry.register(user_id, Role.USER, home_operator, signer.public_key, signer.scheme)
        agent = UserAgent(user_id, account_of(signer), home_operator, signer)
        self.ledger.deposit(agent.account, balance)
        self.users[user_id] = agent
        return agent

    def add_station(self, station_id: str, operator: str, beneficiary: str) -> StationAgent:
        if station_id in self.stations:
            return self.stations[station_id]
        signer = Signer(self.profile.station_sig)
        self.registry.register(station_id, Role.STATION, operator, signer.public_key, signer.scheme)
        self.registry.set_beneficiary(station_id, beneficiary)
        agent = StationAgent(station_id, operator, beneficiary, signer)
        self.stations[station_id] = agent
        return agent

    def add_meter(self, meter_id: str, station_id: str, operator: str) -> MeterDevice:
        if meter_id in self.meters:
            return self.meters[meter_id]
        signer = Signer(self.profile.meter_sig)
        rec = self.registry.register(meter_id, Role.METER, operator, signer.public_key, signer.scheme)
        self.registry.bind_meter(meter_id, station_id)
        dev = MeterDevice(meter_id, station_id, signer, rec.key_epoch)
        self.meters[meter_id] = dev
        return dev

    def register_spec(self, s: SessionSpec) -> None:
        self.add_user(s.user_id, s.home_operator)
        self.add_station(s.station_id, s.foreign_operator, s.beneficiary)
        self.add_meter(s.meter_id, s.station_id, s.foreign_operator)
        self.registry.publish_tariff(s.station_id, s.tariff_id, s.tariff_version, s.tariff_mode, s.unit_price, s.currency)

    def recipients(self) -> list[RecipientKey]:
        return [RecipientKey(r.entity_id, r.key_epoch, r.key_type, r.public_key)
                for r in self.registry.active_verifier_kem_keys()]

    def session(self, spec: SessionSpec) -> "Session":
        self.register_spec(spec)
        return Session(self, spec)

    def run(self, spec: SessionSpec, *, topup: bool = False) -> "SessionResult":
        return self.session(spec).run_all(topup=topup)


@dataclass
class SessionResult:
    ok: bool
    stage: str
    code: str
    tid: str
    captured: Decimal | None = None
    refund: Decimal | None = None
    timings_ms: dict[str, float] = field(default_factory=dict)
    sizes: dict[str, int] = field(default_factory=dict)
    verifier_outcomes: list[VerifierOutcome] = field(default_factory=list)


class Session:
    """One charging session. Each method is one protocol stage."""

    def __init__(self, env: DvasEnvironment, spec: SessionSpec) -> None:
        self.env = env
        self.spec = spec
        self.user = env.users[spec.user_id]
        self.station = env.stations[spec.station_id]
        self.meter = env.meters[spec.meter_id]
        self.timings: dict[str, float] = {}
        self.sizes: dict[str, int] = {}
        self.commitment: Commitment | None = None
        self.values: dict[str, Any] = {}
        self.sid = ""
        self.receipt: PublicReceipt | None = None
        self.envelope: EvidenceEnvelope | None = None
        self.private_values: dict[str, Any] = {}
        self.outcomes: list[VerifierOutcome] = []
        self.rbc: QuorumRBC | None = None

    def _t(self, key: str, t0: float) -> None:
        self.timings[key] = self.timings.get(key, 0.0) + (time.perf_counter() - t0) * 1000.0

    # -- stage 1: commitment --------------------------------------------------
    def layout_values(self) -> dict[str, Any]:
        s = self.spec
        return {
            "protocol_version": PROTOCOL_VERSION_VALUE, "schema_version": LAYOUT_SCHEMA_ID, "tid": s.tid,
            "created_at": s.created_at, "user_id": s.user_id, "user_account": self.user.account,
            "home_operator": s.home_operator, "station_id": s.station_id, "meter_id": s.meter_id,
            "foreign_operator": s.foreign_operator, "beneficiary": s.beneficiary, "evse_id": s.evse_id,
            "tariff_id": s.tariff_id, "tariff_version": s.tariff_version, "tariff_mode": s.tariff_mode,
            "unit_price": s.unit_price, "currency": s.currency, "requested_kwh": s.requested_kwh,
            "cap_kwh": s.cap_kwh, "preauth_limit": s.preauth_limit, "tw_start": s.tw_start, "tw_end": s.tw_end,
            "paytok": build_payment_token(s.tid, self.user.account, s.station_id),
            "payment_semantics": "RESERVE_RELEASE", "nonce_u": s.nonce_u, "nonce_s": s.nonce_s,
        }

    def commit(self, values: dict[str, Any] | None = None) -> Commitment:
        t0 = time.perf_counter()
        self.values = values if values is not None else self.layout_values()
        self.commitment = commit(self.values)
        self._t("commit", t0)
        return self.commitment

    # -- stage 2: authorization ----------------------------------------------
    def auth_request(self) -> dict[str, Any]:
        v = self.commitment.values  # type: ignore[union-attr]
        return {"protocol_version": PROTOCOL_VERSION_VALUE, "tid": v["tid"], "rho_t": self.commitment.rho_t,  # type: ignore[union-attr]
                "user_id": v["user_id"], "user_account": v["user_account"], "preauth_limit": v["preauth_limit"],
                "paytok": v["paytok"], "event_nonce": f"auth-{v['tid']}"}

    def authorize(self, opening: PAMOpening | None = None, request: dict[str, Any] | None = None,
                  signer: Signer | None = None) -> LedgerResult:
        t0 = time.perf_counter()
        req = request or self.auth_request()
        sig = (signer or self.user.signer).sign(auth_request_message(req))
        self._t("auth_sign", t0)
        t0 = time.perf_counter()
        opening = opening or open_for_reason(self.commitment, "authorization", proof_kind=self.env.proof_kind)  # type: ignore[arg-type]
        self._t("open_A", t0)
        self.sizes["opening_A_bytes"] = len(opening.to_bytes())
        t0 = time.perf_counter()
        res = self.env.ledger.authorize(req, sig, opening)
        self._t("authorize_verify", t0)
        return res

    # -- stage 3: session ------------------------------------------------------
    def open_session(self, sid: str | None = None, signer: Signer | None = None) -> LedgerResult:
        t0 = time.perf_counter()
        self.sid = sid or hashlib.sha256(f"sid|{self.spec.tid}|{self.spec.nonce_s}".encode()).hexdigest()[:40]
        vals = {"protocol_version": PROTOCOL_VERSION_VALUE, "tid": self.spec.tid, "sid": self.sid,
                "rho_t": self.commitment.rho_t, "station_id": self.spec.station_id,  # type: ignore[union-attr]
                "meter_id": self.spec.meter_id, "nonce_s": self.spec.nonce_s}
        sig = (signer or self.station.signer).sign(session_open_message(vals))
        res = self.env.ledger.open_session(vals, sig)
        self._t("session_open", t0)
        return res

    # -- stage 4: delivery evidence --------------------------------------------
    def deliver(self, *, recipients: Iterable[RecipientKey] | None = None, meter: MeterDevice | None = None,
                **overrides: Any) -> PublicReceipt:
        s = self.spec
        args = dict(
            tid=s.tid, sid=self.sid, rho_t=self.commitment.rho_t, delivered_kwh=s.delivered_kwh,  # type: ignore[union-attr]
            ts_start=s.ts_start, ts_end=s.ts_end, applied_tariff_id=s.tariff_id,
            applied_tariff_version=s.tariff_version, connection_duration_s=s.connection_duration_s,
            active_charging_duration_s=s.active_charging_duration_s, parking_duration_s=s.parking_duration_s,
            session_ref=s.session_ref or f"row-{s.row_index}", nonce_m=f"m-{s.tid}",
            recipients=list(recipients) if recipients is not None else self.env.recipients(),
            meter_values_digest=s.extra.get("meter_values_digest"),
        )
        args.update(overrides)
        t0 = time.perf_counter()
        dev = meter or self.meter
        self.receipt, self.envelope, self.private_values = dev.issue(**args)
        self._t("receipt_generate", t0)
        for k, v in dev.last_timings.items():
            self.timings[k] = self.timings.get(k, 0.0) + v
        self.sizes["receipt_bytes"] = len(self.receipt.encoded()) + len(self.receipt.signature)
        self.sizes["private_envelope_bytes"] = self.envelope.size_bytes()
        return self.receipt

    def submit_receipt(self, receipt: PublicReceipt | None = None) -> LedgerResult:
        t0 = time.perf_counter()
        res = self.env.ledger.submit_receipt(receipt or self.receipt)  # type: ignore[arg-type]
        self._t("receipt_submit", t0)
        return res

    def topup(self, delta: Decimal | None = None) -> LedgerResult:
        rec = self.env.ledger.records[self.spec.tid]
        d = self.spec.topup_delta if delta is None else delta
        vals = {"protocol_version": PROTOCOL_VERSION_VALUE, "tid": self.spec.tid, "rho_t": rec.rho_t,
                "sid": self.sid or "-", "user_account": rec.user_account, "old_limit": rec.effective_limit,
                "delta_limit": d, "new_limit": rec.effective_limit + d,
                "event_nonce": f"topup-{self.spec.tid}-{rec.topup_count}"}
        t0 = time.perf_counter()
        sig = self.user.signer.sign(topup_message(vals))
        res = self.env.ledger.topup(vals, sig)
        self._t("topup", t0)
        return res

    # -- stage 5: verification -------------------------------------------------
    def settlement_request(self, opening: PAMOpening | None = None) -> SettlementRequest:
        t0 = time.perf_counter()
        opening = opening or open_for_reason(self.commitment, "settlement", proof_kind=self.env.proof_kind)  # type: ignore[arg-type]
        self._t("open_S", t0)
        self.sizes["opening_S_bytes"] = len(opening.to_bytes())
        return SettlementRequest(self.spec.tid, self.receipt, self.envelope, opening)  # type: ignore[arg-type]

    def verify(self, request: SettlementRequest | None = None) -> list[VerifierOutcome]:
        req = request or self.settlement_request()
        self.outcomes = []
        for node in self.env.verifiers.values():
            self.outcomes.append(node.evaluate(req, self.env.registry, self.env.ledger))
        per = [o.timings_ms.get("total", 0.0) for o in self.outcomes]
        self.timings["verifiers_sum"] = sum(per)
        self.timings["verifiers_max"] = max(per) if per else 0.0
        self.timings["private_open_max"] = max((o.timings_ms.get("private_open", 0.0) for o in self.outcomes), default=0.0)
        return self.outcomes

    def aggregate(self) -> QuorumRBC | None:
        t0 = time.perf_counter()
        bodies: dict[str, RBCBody] = {o.body.digest: o.body for o in self.outcomes if o.body is not None}
        self.rbc = aggregate([o.attestation for o in self.outcomes if o.attestation], bodies, self.env.ledger.policy.t)
        self._t("rbc_aggregate", t0)
        if self.rbc:
            self.sizes["rbc_bytes"] = self.rbc.size_bytes()
        return self.rbc

    def settle(self, rbc: QuorumRBC | None = None) -> LedgerResult:
        t0 = time.perf_counter()
        res = self.env.ledger.settle(rbc or self.rbc)  # type: ignore[arg-type]
        self._t("settle", t0)
        return res

    # -- full run --------------------------------------------------------------
    def run_all(self, *, topup: bool = False) -> SessionResult:
        tid = self.spec.tid
        self.commit()
        steps = [("authorize", self.authorize), ("open_session", self.open_session)]
        for name, fn in steps:
            r = fn()
            if not r.ok:
                return SessionResult(False, name, r.code, tid, timings_ms=self.timings, sizes=self.sizes)
        self.deliver()
        r = self.submit_receipt()
        if not r.ok:
            return SessionResult(False, "submit_receipt", r.code, tid, timings_ms=self.timings, sizes=self.sizes)
        if topup and self.spec.topup_delta > 0:
            r = self.topup()
            if not r.ok:
                return SessionResult(False, "topup", r.code, tid, timings_ms=self.timings, sizes=self.sizes)
        self.verify()
        if self.aggregate() is None:
            reasons = ";".join(f"{o.verifier_id}:{o.reason}" for o in self.outcomes if not o.ok)
            return SessionResult(False, "quorum", f"NO_QUORUM[{reasons}]", tid, timings_ms=self.timings,
                                 sizes=self.sizes, verifier_outcomes=self.outcomes)
        r = self.settle()
        if not r.ok:
            return SessionResult(False, "settle", r.code, tid, timings_ms=self.timings, sizes=self.sizes,
                                 verifier_outcomes=self.outcomes)
        self.timings["total"] = sum(v for k, v in self.timings.items()
                                    if k not in ("verifiers_sum", "private_open_max", "total", "receipt_sign",
                                                 "private_protect"))
        return SessionResult(True, "settled", "OK", tid, r.value["captured"], r.value["refund"], self.timings,
                             self.sizes, self.outcomes)
