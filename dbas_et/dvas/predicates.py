"""
Restricted predicate language and dependency registry for PA-MSP.

PA-MSP = Predicate-Aware Multi-Stage Projection.  The selector here is
dependency based: for a verification reason r it returns the committed operands
that the predicate for r reads.  Minimality is checked separately in
``minimality.py`` and ``minimality_exact.py``.

Language
--------
Terms   C(name)          committed operand (a PRE_SERVICE_COMMITTED field)
        E(name)          evidence operand (receipt, ledger state, request)
        K(value)         constant
        O(name)          derived output defined by the predicate
        Tariff(...)      deterministic tariff function over terms
Atoms   Cmp(op, a, b)    op in {EQ, NE, LT, LE, GT, GE}
        Rel(name, *args) registry relation evaluated by the caller
Pred    conjunction of atoms with optional derived outputs.

Evaluation never substitutes defaults: if a committed operand is absent the
result is ``missing_operand`` and the predicate is false.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Callable, Mapping, Union

from .schema import LAYOUT_V1, PRE, REGISTRY, LayoutSchema, PROTOCOL_VERSION_VALUE
from .tariff import tariff_amount


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class C:
    name: str


@dataclass(frozen=True)
class E:
    name: str


@dataclass(frozen=True)
class K:
    value: Any


@dataclass(frozen=True)
class O:
    name: str


@dataclass(frozen=True)
class Tariff:
    mode: "Term"
    unit_price: "Term"
    delivered_kwh: "Term"
    connection_duration_s: "Term"
    active_charging_duration_s: "Term"
    parking_duration_s: "Term"


Term = Union[C, E, K, O, Tariff]


@dataclass(frozen=True)
class Cmp:
    op: str
    left: Term
    right: Term
    label: str = ""


@dataclass(frozen=True)
class Rel:
    name: str
    args: tuple[Term, ...]
    label: str = ""


Atom = Union[Cmp, Rel]


@dataclass(frozen=True)
class Predicate:
    predicate_id: str
    atoms: tuple[Atom, ...]
    outputs: tuple[tuple[str, Term], ...] = ()
    description: str = ""


def _term_committed(t: Term) -> set[str]:
    if isinstance(t, C):
        return {t.name}
    if isinstance(t, Tariff):
        out: set[str] = set()
        for sub in (t.mode, t.unit_price, t.delivered_kwh, t.connection_duration_s,
                    t.active_charging_duration_s, t.parking_duration_s):
            out |= _term_committed(sub)
        return out
    return set()


def _term_outputs(t: Term) -> set[str]:
    if isinstance(t, O):
        return {t.name}
    if isinstance(t, Tariff):
        out: set[str] = set()
        for sub in (t.mode, t.unit_price, t.delivered_kwh, t.connection_duration_s,
                    t.active_charging_duration_s, t.parking_duration_s):
            out |= _term_outputs(sub)
        return out
    return set()


def atom_terms(a: Atom) -> tuple[Term, ...]:
    return (a.left, a.right) if isinstance(a, Cmp) else a.args


def committed_operands(pred: Predicate) -> frozenset[str]:
    """Committed operands read by the predicate (including through outputs)."""
    defs = dict(pred.outputs)
    used_outputs: set[str] = set()
    out: set[str] = set()
    for a in pred.atoms:
        for t in atom_terms(a):
            out |= _term_committed(t)
            used_outputs |= _term_outputs(t)
    for name in sorted(used_outputs):
        out |= _term_committed(defs[name])
    return frozenset(out)


def atom_committed(pred: Predicate, a: Atom) -> frozenset[str]:
    defs = dict(pred.outputs)
    out: set[str] = set()
    for t in atom_terms(a):
        out |= _term_committed(t)
        for o in _term_outputs(t):
            out |= _term_committed(defs[o])
    return frozenset(out)


# ---------------------------------------------------------------------------
# Predicate registry
# ---------------------------------------------------------------------------

def _eq(a: Term, b: Term, label: str = "") -> Cmp:
    return Cmp("EQ", a, b, label)


def _le(a: Term, b: Term, label: str = "") -> Cmp:
    return Cmp("LE", a, b, label)


def _ge(a: Term, b: Term, label: str = "") -> Cmp:
    return Cmp("GE", a, b, label)


def _lt(a: Term, b: Term, label: str = "") -> Cmp:
    return Cmp("LT", a, b, label)


def _gt(a: Term, b: Term, label: str = "") -> Cmp:
    return Cmp("GT", a, b, label)


AMOUNT = (
    "amount",
    Tariff(C("tariff_mode"), C("unit_price"), E("delivered_kwh"), E("connection_duration_s"),
           E("active_charging_duration_s"), E("parking_duration_s")),
)

TID_BINDING = (_eq(C("tid"), E("receipt_tid"), "tid_binding"),)

STATION_METER_BINDING = (
    _eq(C("station_id"), E("receipt_station_id"), "station_match"),
    _eq(C("meter_id"), E("receipt_meter_id"), "meter_match"),
    Rel("meter_bound_to_station", (C("meter_id"), C("station_id")), "registry_meter_station"),
    Rel("station_operated_by", (C("station_id"), C("foreign_operator")), "registry_station_operator"),
)

PRICING = (
    _eq(C("tariff_id"), E("applied_tariff_id"), "tariff_id_match"),
    _eq(C("tariff_version"), E("applied_tariff_version"), "tariff_version_match"),
    _eq(C("currency"), E("settlement_currency"), "currency_match"),
    _ge(O("amount"), K(Decimal(0)), "amount_defined"),
)

TIME_WINDOW = (
    _ge(E("ts_start"), C("tw_start"), "start_in_window"),
    _le(E("ts_end"), C("tw_end"), "end_in_window"),
    _le(E("ts_start"), E("ts_end"), "ordered_timestamps"),
)

DELIVERY_CAP = (
    _ge(E("delivered_kwh"), K(Decimal(0)), "energy_nonnegative"),
    _le(E("delivered_kwh"), C("cap_kwh"), "energy_within_cap"),
)

RESERVE_AMOUNT = (
    _le(C("preauth_limit"), E("effective_limit"), "limit_not_decreased"),
    _le(O("amount"), E("effective_limit"), "amount_within_effective_limit"),
    _le(O("amount"), E("held_amount"), "amount_within_hold"),
)

REPLAY = (
    _eq(C("tid"), E("receipt_tid"), "tid_binding"),
    _eq(C("station_id"), E("receipt_station_id"), "station_match"),
    _eq(C("meter_id"), E("receipt_meter_id"), "meter_match"),
    Rel("fresh_receipt", (E("dr_digest"),), "receipt_not_consumed"),
    Rel("fresh_session", (C("tid"), E("sid")), "session_open_for_tid"),
)

PAYMENT_BINDING = (
    _eq(C("beneficiary"), E("payee"), "beneficiary_match"),
    _eq(C("paytok"), E("ledger_paytok"), "paytok_match"),
)

AUTHORIZATION = (
    _eq(C("protocol_version"), K(PROTOCOL_VERSION_VALUE), "protocol_version"),
    _eq(C("tid"), E("request_tid"), "tid_binding"),
    _eq(C("user_id"), E("request_user_id"), "user_match"),
    _eq(C("user_account"), E("request_user_account"), "account_match"),
    Rel("user_home_operator", (C("user_id"), C("home_operator")), "registry_user_home"),
    Rel("meter_bound_to_station", (C("meter_id"), C("station_id")), "registry_meter_station"),
    Rel("station_operated_by", (C("station_id"), C("foreign_operator")), "registry_station_operator"),
    Rel("station_beneficiary", (C("station_id"), C("beneficiary")), "registry_beneficiary"),
    Rel("tariff_published", (C("station_id"), C("tariff_id"), C("tariff_version"), C("tariff_mode"),
                             C("unit_price"), C("currency")), "tariff_catalog"),
    _eq(C("paytok"), E("request_paytok"), "paytok_match"),
    _eq(C("payment_semantics"), K("RESERVE_RELEASE"), "reserve_release"),
    _gt(C("preauth_limit"), K(Decimal(0)), "positive_limit"),
    _le(C("preauth_limit"), E("available_balance"), "sufficient_balance"),
    _le(C("requested_kwh"), C("cap_kwh"), "request_within_cap"),
    _lt(C("tw_start"), C("tw_end"), "valid_window"),
)

PREDICATES: dict[str, Predicate] = {
    "authorization": Predicate("P.authorization", AUTHORIZATION, (), "pre-service admission and reserve"),
    "replay": Predicate("P.replay", REPLAY, (), "receipt/session freshness for this transaction"),
    "station_meter_binding": Predicate("P.station_meter", TID_BINDING + STATION_METER_BINDING, (),
                                       "receipt station/meter bound to committed and registered pair"),
    "pricing": Predicate("P.pricing", TID_BINDING + PRICING, (AMOUNT,), "applied tariff equals committed tariff"),
    "time_window": Predicate("P.time_window", TID_BINDING + TIME_WINDOW, (), "delivery inside committed window"),
    "delivery_cap": Predicate("P.delivery_cap", TID_BINDING + DELIVERY_CAP, (), "delivered energy within cap"),
    "reserve_amount": Predicate("P.reserve_amount", TID_BINDING + RESERVE_AMOUNT, (AMOUNT,),
                                "tariff amount within reserve/hold"),
    "settlement": Predicate(
        "P.settlement",
        TID_BINDING + STATION_METER_BINDING + PRICING + TIME_WINDOW + DELIVERY_CAP + RESERVE_AMOUNT + PAYMENT_BINDING,
        (AMOUNT,),
        "Match(S_t, DR_t): full settlement predicate",
    ),
    "dispute:over_cap": Predicate("P.dispute.over_cap", TID_BINDING + STATION_METER_BINDING[:2] + DELIVERY_CAP, (),
                                  "dispute: delivered energy exceeds committed cap"),
    "dispute:tariff_mismatch": Predicate("P.dispute.tariff", TID_BINDING + PRICING[:2], (),
                                         "dispute: applied tariff differs from committed tariff"),
    "dispute:time_window": Predicate("P.dispute.time", TID_BINDING + TIME_WINDOW, (),
                                     "dispute: delivery outside committed window"),
    "dispute:amount_exceeds_preauth": Predicate("P.dispute.amount", TID_BINDING + RESERVE_AMOUNT, (AMOUNT,),
                                                "dispute: settled amount exceeds pre-authorised reserve"),
    "dispute:replay": Predicate("P.dispute.replay", REPLAY, (), "dispute: replayed receipt or session"),
}


def predicate_for(reason: str) -> Predicate:
    return PREDICATES[reason]


_REQ_CACHE: dict[tuple[LayoutSchema, str], tuple[str, ...]] = {}


def required_fields(schema: LayoutSchema, reason: str) -> tuple[str, ...]:
    """F_req = committed operands of predicate(reason), ordered by field id.

    Deterministic and schema-checked: every operand must be a committed field
    of ``schema``.  Memoised: the predicate registry is static.
    """
    hit = _REQ_CACHE.get((schema, reason))
    if hit is not None:
        return hit
    pred = PREDICATES[reason]
    ops = committed_operands(pred)
    for n in ops:
        spec = REGISTRY.spec(n)
        if spec.lifecycle != PRE or n not in schema.field_names:
            raise ValueError(f"predicate {reason} references non-committed operand {n}")
    out = tuple(sorted(ops, key=lambda n: REGISTRY.spec(n).field_id))
    _REQ_CACHE[(schema, reason)] = out
    return out


def dependency_table(schema: LayoutSchema = LAYOUT_V1) -> list[dict[str, Any]]:
    """Per-reason, per-atom dependency derivation (for reports)."""
    rows = []
    for reason, pred in PREDICATES.items():
        for a in pred.atoms:
            rows.append({
                "reason": reason,
                "predicate_id": pred.predicate_id,
                "atom": a.label,
                "committed_operands": ",".join(sorted(atom_committed(pred, a))),
            })
    return rows


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

class MissingOperand(Exception):
    def __init__(self, kind: str, name: str) -> None:
        super().__init__(f"{kind}:{name}")
        self.kind = kind
        self.name = name


@dataclass(frozen=True)
class PredicateResult:
    ok: bool
    failed: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    outputs: dict[str, Any] = field(default_factory=dict)

    @property
    def reason(self) -> str:
        if self.missing:
            return "missing_operand:" + ",".join(self.missing)
        return ",".join(self.failed)


RelationFn = Callable[..., bool]


def _num(v: Any) -> Any:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, Decimal)):
        return v
    if isinstance(v, float):
        return Decimal(repr(v))
    return v


def _eval(t: Term, committed: Mapping[str, Any], evidence: Mapping[str, Any], outputs: Mapping[str, Any]) -> Any:
    if isinstance(t, C):
        if t.name not in committed:
            raise MissingOperand("committed", t.name)
        return _num(committed[t.name])
    if isinstance(t, E):
        if t.name not in evidence:
            raise MissingOperand("evidence", t.name)
        return _num(evidence[t.name])
    if isinstance(t, K):
        return t.value
    if isinstance(t, O):
        return outputs[t.name]
    if isinstance(t, Tariff):
        return tariff_amount(
            mode=str(_eval(t.mode, committed, evidence, outputs)),
            unit_price=Decimal(_eval(t.unit_price, committed, evidence, outputs)),
            delivered_kwh=Decimal(_eval(t.delivered_kwh, committed, evidence, outputs)),
            connection_duration_s=int(_eval(t.connection_duration_s, committed, evidence, outputs)),
            active_charging_duration_s=int(_eval(t.active_charging_duration_s, committed, evidence, outputs)),
            parking_duration_s=int(_eval(t.parking_duration_s, committed, evidence, outputs)),
        )
    raise TypeError(f"unknown term {t!r}")


_OPS = {
    "EQ": lambda a, b: a == b,
    "NE": lambda a, b: a != b,
    "LT": lambda a, b: a < b,
    "LE": lambda a, b: a <= b,
    "GT": lambda a, b: a > b,
    "GE": lambda a, b: a >= b,
}


def evaluate(
    pred: Predicate,
    committed: Mapping[str, Any],
    evidence: Mapping[str, Any],
    relations: Mapping[str, RelationFn] | None = None,
) -> PredicateResult:
    relations = relations or {}
    missing: list[str] = []
    failed: list[str] = []
    outputs: dict[str, Any] = {}
    for name, term in pred.outputs:
        try:
            outputs[name] = _eval(term, committed, evidence, outputs)
        except MissingOperand as m:
            missing.append(str(m))
        except (ValueError, ArithmeticError) as exc:
            failed.append(f"output_{name}_invalid:{exc}")
    if missing or failed:  # never evaluate atoms over an undefined derived output
        return PredicateResult(False, tuple(failed), tuple(sorted(set(missing))), outputs)
    for a in pred.atoms:
        try:
            if isinstance(a, Cmp):
                l = _eval(a.left, committed, evidence, outputs)
                r = _eval(a.right, committed, evidence, outputs)
                try:
                    ok = bool(_OPS[a.op](l, r))
                except TypeError:
                    ok = False
            else:
                args = [_eval(t, committed, evidence, outputs) for t in a.args]
                fn = relations.get(a.name)
                if fn is None:
                    raise MissingOperand("relation", a.name)
                ok = bool(fn(*args))
        except MissingOperand as m:
            missing.append(str(m))
            continue
        if not ok:
            failed.append(a.label or a.name if isinstance(a, Rel) else a.label or a.op)
    if missing:
        return PredicateResult(False, tuple(failed), tuple(sorted(set(missing))), outputs)
    return PredicateResult(not failed, tuple(failed), (), outputs)
