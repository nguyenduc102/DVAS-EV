"""
Controlled architectural baselines with a common lifecycle interface.

These are CONTROLLED ARCHITECTURAL BASELINES built from the same primitives
(canonical encoder, ECDSA/ML-DSA signers, SHA-256, instrumentation) as
DVAS-EV.  They are not reproductions of external state-of-the-art systems.

    authorize()  submit_receipt()  verify_delivery()  settle()

FullEscrow   full capsule and full receipt posted publicly; the contract
             evaluates the settlement predicate itself (no proofs, no privacy).
HashAnchor   only H(capsule) and H(receipt) on chain; a single trusted
             operator checks semantics off-chain and signs the settlement
             claim; the contract checks the signature and amount <= hold.
CDR          OCPI-style post-hoc Charge Detail Record: no pre-service
             commitment; CPO signs a CDR with the tariff it applied; eMSP
             verifies CDR + meter signatures and pays if cost <= reserve.
DVAS-EV      committed capsule, predicate-complete PAM openings, meter-bound
             private evidence, 2-of-3 quorum RBC.

Every baseline also executes the same three attack inputs so that the
detection comparison is measured rather than asserted.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from decimal import Decimal
from typing import Any

from .canonical import RecordType, encode_record, tagged_hash
from .instrumentation import OpCounter, count
from .pam import open_for_reason
from .predicates import evaluate, predicate_for
from .profiles import ECDSA, PROFILES, CryptoProfile, Signer, verify_signature
from .protocol import DvasEnvironment, Session
from .schema import LAYOUT_V1, PRE, PUBLIC_RECEIPT, REGISTRY
from .tariff import tariff_amount
from .workload import SessionSpec
from .workload import honest_amount as _exact_amount

FULL_CAPSULE = RecordType(0x0F01, "baseline_full_capsule", LAYOUT_V1.field_names)
FULL_RECEIPT = RecordType(0x0F02, "baseline_full_receipt", PUBLIC_RECEIPT.field_names + (
    "connection_duration_s", "active_charging_duration_s", "parking_duration_s", "session_ref"))
PHASES = ("authorize", "submit_receipt", "verify_delivery", "settle")


@dataclass
class PhaseRecord:
    ms: float = 0.0
    ops: dict[str, int] = field(default_factory=dict)


@dataclass
class LifecycleRun:
    baseline: str
    ok: bool
    captured: Decimal | None
    phases: dict[str, PhaseRecord]
    public_bytes: int
    private_bytes: int
    retained_objects: int


class _Parties:
    def __init__(self, profile: CryptoProfile) -> None:
        self.user = Signer(profile.auth_sig)
        self.meter = Signer(ECDSA)
        self.operator = Signer(ECDSA)


class LifecycleBaseline:
    name = "abstract"

    def __init__(self, profile: CryptoProfile = PROFILES["C0"]) -> None:
        self.profile = profile
        self.parties = _Parties(profile)  # key generation is setup, outside timed phases
        self.public_bytes = 0
        self.private_bytes = 0
        self.retained = 0

    # lifecycle (override) -------------------------------------------------
    def prepare(self, spec: SessionSpec, ctx: dict) -> None:
        """Untimed setup (registration / key provisioning)."""
        ctx["p"] = self.parties

    def authorize(self, spec: SessionSpec, ctx: dict) -> bool: ...
    def submit_receipt(self, spec: SessionSpec, ctx: dict) -> bool: ...
    def verify_delivery(self, spec: SessionSpec, ctx: dict) -> bool: ...
    def settle(self, spec: SessionSpec, ctx: dict) -> Decimal | None: ...

    # helpers ---------------------------------------------------------------
    def _pub(self, n: int, retain: bool = False) -> None:
        self.public_bytes += n
        count("public_bytes", n)
        if retain:
            self.retained += 1
            count("retained_object")

    def _priv(self, n: int, retain: bool = False) -> None:
        self.private_bytes += n
        count("private_bytes", n)
        if retain:
            self.retained += 1
            count("retained_object")

    def run(self, spec: SessionSpec, mutate: dict[str, Any] | None = None) -> LifecycleRun:
        self.public_bytes = self.private_bytes = self.retained = 0
        ctx: dict[str, Any] = {"mutate": mutate or {}}
        phases: dict[str, PhaseRecord] = {}
        ok, captured = True, None
        self.prepare(spec, ctx)
        for ph in PHASES:
            with OpCounter() as oc:
                t0 = time.perf_counter()
                res = getattr(self, ph)(spec, ctx)
                ms = (time.perf_counter() - t0) * 1000.0
            phases[ph] = PhaseRecord(ms, oc.as_dict())
            if ph == "settle":
                captured = res
                ok = res is not None
            elif not res:
                ok = False
                break
        return LifecycleRun(self.name, ok, captured, phases, self.public_bytes, self.private_bytes, self.retained)


def _layout_values(spec: SessionSpec, account: str) -> dict[str, Any]:
    from ..capsule import build_payment_token
    from .schema import LAYOUT_SCHEMA_ID, PROTOCOL_VERSION_VALUE

    return {
        "protocol_version": PROTOCOL_VERSION_VALUE, "schema_version": LAYOUT_SCHEMA_ID, "tid": spec.tid,
        "created_at": spec.created_at, "user_id": spec.user_id, "user_account": account,
        "home_operator": spec.home_operator, "station_id": spec.station_id, "meter_id": spec.meter_id,
        "foreign_operator": spec.foreign_operator, "beneficiary": spec.beneficiary, "evse_id": spec.evse_id,
        "tariff_id": spec.tariff_id, "tariff_version": spec.tariff_version, "tariff_mode": spec.tariff_mode,
        "unit_price": spec.unit_price, "currency": spec.currency, "requested_kwh": spec.requested_kwh,
        "cap_kwh": spec.cap_kwh, "preauth_limit": spec.preauth_limit, "tw_start": spec.tw_start,
        "tw_end": spec.tw_end, "paytok": build_payment_token(spec.tid, account, spec.station_id),
        "payment_semantics": "RESERVE_RELEASE", "nonce_u": spec.nonce_u, "nonce_s": spec.nonce_s,
    }


def _delivery(spec: SessionSpec, mutate: dict[str, Any]) -> dict[str, Any]:
    d = {
        "delivered_kwh": spec.delivered_kwh, "ts_start": spec.ts_start, "ts_end": spec.ts_end,
        "applied_tariff_id": spec.tariff_id, "applied_tariff_version": spec.tariff_version,
        "applied_unit_price": spec.unit_price,
        "connection_duration_s": spec.connection_duration_s,
        "active_charging_duration_s": spec.active_charging_duration_s,
        "parking_duration_s": spec.parking_duration_s,
    }
    d.update({k: v for k, v in mutate.items() if k in d})
    return d


def _receipt_values(spec: SessionSpec, d: dict[str, Any], rho: str = "00" * 32) -> dict[str, Any]:
    return {
        "receipt_version": "baseline", "receipt_tid": spec.tid, "sid": f"sid-{spec.tid}", "rho_t": rho,
        "receipt_station_id": spec.station_id, "receipt_meter_id": spec.meter_id,
        "delivered_kwh": d["delivered_kwh"], "ts_start": d["ts_start"], "ts_end": d["ts_end"],
        "applied_tariff_id": d["applied_tariff_id"], "applied_tariff_version": d["applied_tariff_version"],
        "nonce_m": f"m-{spec.tid}", "h_priv": "00" * 32, "meter_key_epoch": 1,
    }


def _amount(mode: str, price: Decimal, d: dict[str, Any]) -> Decimal:
    return tariff_amount(mode=mode, unit_price=price, delivered_kwh=d["delivered_kwh"],
                         connection_duration_s=d["connection_duration_s"],
                         active_charging_duration_s=d["active_charging_duration_s"],
                         parking_duration_s=d["parking_duration_s"])


class FullEscrow(LifecycleBaseline):
    name = "FullEscrow"

    def authorize(self, spec, ctx):
        p = ctx["p"]
        vals = _layout_values(spec, "acct")
        b = encode_record(REGISTRY, FULL_CAPSULE, vals)
        sig = p.user.sign(tagged_hash("baseline/capsule", b))
        self._pub(len(b) + len(sig), retain=True)
        ok = verify_signature(p.user.scheme, p.user.public_key, tagged_hash("baseline/capsule", b), sig)
        count("bound_check")
        ctx["capsule"], ctx["held"] = vals, spec.preauth_limit
        count("state_transition")
        return ok

    def submit_receipt(self, spec, ctx):
        d = ctx["d"] = _delivery(spec, ctx["mutate"])
        rv = _receipt_values(spec, d) | {k: d[k] for k in ("connection_duration_s", "active_charging_duration_s",
                                                            "parking_duration_s")} | {"session_ref": spec.session_ref}
        b = encode_record(REGISTRY, FULL_RECEIPT, rv)
        sig = ctx["p"].meter.sign(tagged_hash("baseline/receipt", b))
        self._pub(len(b) + len(sig), retain=True)
        count("state_transition")
        return verify_signature(ECDSA, ctx["p"].meter.public_key, tagged_hash("baseline/receipt", b), sig)

    def verify_delivery(self, spec, ctx):
        c, d = ctx["capsule"], ctx["d"]
        ev = {"receipt_tid": spec.tid, "receipt_station_id": spec.station_id, "receipt_meter_id": spec.meter_id,
              "applied_tariff_id": d["applied_tariff_id"], "applied_tariff_version": d["applied_tariff_version"],
              "settlement_currency": spec.currency, "delivered_kwh": d["delivered_kwh"], "ts_start": d["ts_start"],
              "ts_end": d["ts_end"], "connection_duration_s": d["connection_duration_s"],
              "active_charging_duration_s": d["active_charging_duration_s"],
              "parking_duration_s": d["parking_duration_s"], "effective_limit": ctx["held"],
              "held_amount": ctx["held"], "payee": spec.beneficiary, "ledger_paytok": c["paytok"]}
        rel = {"meter_bound_to_station": lambda m, s: True, "station_operated_by": lambda s, o: True}
        res = evaluate(predicate_for("settlement"), c, ev, rel)
        ctx["amount"] = res.outputs.get("amount")
        count("bound_check", 3)
        return res.ok

    def settle(self, spec, ctx):
        amt = ctx["amount"]
        claimed = ctx["mutate"].get("claimed_amount")
        if claimed is not None and claimed != amt:  # contract computes the amount itself
            return None
        count("bound_check", 2)
        count("state_transition")
        self._pub(64)
        return amt if amt is not None and amt <= ctx["held"] else None


class HashAnchor(LifecycleBaseline):
    name = "HashAnchor"

    def authorize(self, spec, ctx):
        p = ctx["p"]
        vals = _layout_values(spec, "acct")
        b = encode_record(REGISTRY, FULL_CAPSULE, vals)
        h = tagged_hash("baseline/capsule", b)
        sig = p.user.sign(h)
        self._priv(len(b), retain=True)  # capsule held by operators off-chain
        self._pub(32 + len(sig), retain=True)
        ctx["capsule"], ctx["h_capsule"], ctx["held"] = vals, h, spec.preauth_limit
        count("state_transition")
        return verify_signature(p.user.scheme, p.user.public_key, h, sig)

    def submit_receipt(self, spec, ctx):
        d = ctx["d"] = _delivery(spec, ctx["mutate"])
        b = encode_record(REGISTRY, PUBLIC_RECEIPT, _receipt_values(spec, d))
        h = tagged_hash("baseline/receipt", b)
        sig = ctx["p"].meter.sign(h)
        self._priv(len(b) + len(sig), retain=True)
        self._pub(32, retain=True)
        ctx["h_receipt"] = h
        count("state_transition")
        return verify_signature(ECDSA, ctx["p"].meter.public_key, h, sig)

    def verify_delivery(self, spec, ctx):
        # single trusted operator: computes the amount with the tariff it APPLIED (no committed binding)
        d = ctx["d"]
        ctx["amount"] = _amount(spec.tariff_mode, d["applied_unit_price"], d)
        claim = tagged_hash("baseline/claim", ctx["h_capsule"], ctx["h_receipt"], str(ctx["amount"]).encode())
        ctx["claim_sig"] = ctx["p"].operator.sign(claim)
        ctx["claim"] = claim
        return True

    def settle(self, spec, ctx):
        amt = ctx["mutate"].get("claimed_amount", ctx["amount"])
        claim = tagged_hash("baseline/claim", ctx["h_capsule"], ctx["h_receipt"], str(amt).encode())
        sig = ctx["p"].operator.sign(claim) if amt != ctx["amount"] else ctx["claim_sig"]
        self._pub(32 * 3 + len(sig) + 16)
        ok = verify_signature(ECDSA, ctx["p"].operator.public_key, claim, sig)
        count("bound_check")
        count("state_transition")
        return amt if ok and amt <= ctx["held"] else None


class CDR(LifecycleBaseline):
    name = "CDR"

    def authorize(self, spec, ctx):
        p = ctx["p"]
        token = encode_record(REGISTRY, RecordType(0x0F03, "baseline_auth", ("tid", "user_id", "preauth_limit")),
                              {"tid": spec.tid, "user_id": spec.user_id, "preauth_limit": spec.preauth_limit})
        sig = p.user.sign(tagged_hash("baseline/auth", token))
        self._priv(len(token) + len(sig), retain=True)  # eMSP authorization record
        ctx["held"] = spec.preauth_limit
        count("bound_check")
        count("state_transition")
        return verify_signature(p.user.scheme, p.user.public_key, tagged_hash("baseline/auth", token), sig)

    def submit_receipt(self, spec, ctx):
        d = ctx["d"] = _delivery(spec, ctx["mutate"])
        b = encode_record(REGISTRY, PUBLIC_RECEIPT, _receipt_values(spec, d))
        ctx["mv"] = b
        ctx["mv_sig"] = ctx["p"].meter.sign(tagged_hash("baseline/receipt", b))
        self._priv(len(b) + len(ctx["mv_sig"]))
        return True

    def verify_delivery(self, spec, ctx):
        d = ctx["d"]
        cost = _amount(spec.tariff_mode, d["applied_unit_price"], d)  # CPO's applied tariff, no committed binding
        ctx["cost"] = ctx["mutate"].get("claimed_amount", cost)
        cdr = ctx["mv"] + str(ctx["cost"]).encode() + d["applied_tariff_id"].encode()
        sig = ctx["p"].operator.sign(tagged_hash("baseline/cdr", cdr))
        self._priv(len(cdr) + len(sig), retain=True)  # CDR stored by CPO and eMSP
        self._priv(0, retain=True)
        ok = verify_signature(ECDSA, ctx["p"].operator.public_key, tagged_hash("baseline/cdr", cdr), sig)
        ok &= verify_signature(ECDSA, ctx["p"].meter.public_key, tagged_hash("baseline/receipt", ctx["mv"]), ctx["mv_sig"])
        return ok

    def settle(self, spec, ctx):
        count("bound_check")
        count("state_transition")
        return ctx["cost"] if ctx["cost"] <= ctx["held"] else None


class DVASEV(LifecycleBaseline):
    name = "DVAS-EV"

    def __init__(self, profile: CryptoProfile = PROFILES["C3"]) -> None:
        super().__init__(profile)
        self.env = DvasEnvironment(profile=profile)

    def prepare(self, spec, ctx):
        self.env.register_spec(spec)
        ctx["s"] = self.env.session(spec)

    def authorize(self, spec, ctx):
        s: Session = ctx["s"]
        s.commit()
        r = s.authorize()
        self._pub(s.sizes["opening_A_bytes"] + 200, retain=True)
        return r.ok

    def submit_receipt(self, spec, ctx):
        s: Session = ctx["s"]
        assert s.open_session().ok
        m = ctx["mutate"]
        kw = {k: v for k, v in {"delivered_kwh": m.get("delivered_kwh"),
                               "applied_tariff_version": m.get("applied_tariff_version")}.items() if v is not None}
        s.deliver(**kw)
        self._pub(s.sizes["receipt_bytes"], retain=True)
        self._priv(s.sizes["private_envelope_bytes"])
        return s.submit_receipt().ok

    def verify_delivery(self, spec, ctx):
        s: Session = ctx["s"]
        s.verify()
        self._priv(s.sizes["opening_S_bytes"] * len(s.outcomes))
        rbc = s.aggregate()
        if rbc is not None and "claimed_amount" in ctx["mutate"]:
            # one settlement signer (SV1) inflates; it cannot replace the quorum's digest
            from .rbc import QuorumRBC, RBCBody

            b = rbc.body
            held = self.env.ledger.records[spec.tid].held
            amt = min(ctx["mutate"]["claimed_amount"], held)
            forged = RBCBody.build(**{**b.values, "captured_amount": amt, "refund_amount": held - amt})
            rbc = QuorumRBC(forged, rbc.attestations)
        ctx["rbc"] = rbc
        return rbc is not None

    def settle(self, spec, ctx):
        r = ctx["s"].settle(ctx["rbc"])
        if r.ok:
            self._pub(ctx["rbc"].size_bytes(), retain=True)
            return r.value["captured"]
        return None


BASELINES = {"FullEscrow": FullEscrow, "HashAnchor": HashAnchor, "CDR": CDR, "DVAS-EV": DVASEV}

# Same three attack inputs for every baseline.  Each keeps the resulting amount
# INSIDE the user's hold, so a refusal can only come from a semantic check,
# not from the reserve bound.  criterion: "refuse" = the only correct outcome
# is refusal; "refuse_or_honest" = refusal or settling the honest amount.
def _attack_inputs(spec: SessionSpec, attack: str) -> tuple[SessionSpec, dict[str, Any], str]:
    if attack == "post_authorization_tariff_swap":
        return spec, {"applied_tariff_version": spec.tariff_version + "-swap",
                      "applied_unit_price": (spec.unit_price * Decimal("1.05")).quantize(Decimal("0.000001"))}, "refuse_or_honest"
    if attack == "over_cap_delivery":
        cap = spec.delivered_kwh - Decimal("0.5")
        return replace(spec, cap_kwh=cap, requested_kwh=min(spec.requested_kwh, cap)), {}, "refuse"
    if attack == "single_signer_inflated_amount":
        held = spec.preauth_limit
        return spec, {"claimed_amount": min(held, _exact_amount(spec) + Decimal("0.01"))}, "refuse_or_honest"
    raise KeyError(attack)


ATTACKS = ("post_authorization_tariff_swap", "over_cap_delivery", "single_signer_inflated_amount")


def eligible(spec: SessionSpec) -> bool:
    """Rows where every attack stays inside the hold (fair semantic comparison)."""
    return (spec.delivered_kwh > Decimal("1") and spec.preauth_limit >= _exact_amount(spec) * Decimal("1.06")
            and spec.preauth_limit >= _exact_amount(spec) + Decimal("0.01"))


def detects(b: LifecycleBaseline, spec: SessionSpec, attack: str) -> tuple[bool, str]:
    from .attacks import unique

    sp, mutate, criterion = _attack_inputs(unique(spec, f"bl:{b.name}:{attack}"), attack)
    run = b.run(sp, mutate)
    if not run.ok:
        return True, "refused"
    honest = run.captured == _exact_amount(spec)
    if criterion == "refuse":
        return False, f"settled:{run.captured}"
    return honest, "settled_honest_amount" if honest else f"settled_wrong_amount:{run.captured}"
