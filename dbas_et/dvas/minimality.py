"""
Checked minimality analysis for the restricted DVAS-EV predicate language.

Analysis only.  The runtime selector (``predicates.required_fields``) is
dependency based and is not changed by this module.

Definitions
-----------
S sufficient for P (Boolean):  c1|S == c2|S  =>  P(c1,e) == P(c2,e)   for all e
S sufficient for the decision: additionally the derived outputs (e.g. amount) agree.
Sufficiency is monotone, so F_r is set-inclusion minimal iff every f in F_r
is necessary, and f is necessary iff a WITNESS (c1, c2, e) exists with c1, c2
differing only in f and different outcome.

Valid semantic domain (explicit, per field type)
  STRING     non-empty NFC strings
  ENUM       the registered enum values only
  FIXED6     non-negative values
  TIMESTAMP  integers
Witness search draws alternatives from these domains; evidence is taken from a
real session plus "tightened" variants that make bound atoms active.

Non-necessity certificates (needed to classify a predicate as non-minimal;
absence of a witness alone proves nothing):
  SINGLETON_DOMAIN  the field's valid domain has exactly one value, so any
                    two valid assignments agree on it.
  VACUOUS_ATOM      every atom reading the field is valid-domain-vacuous by a
                    registered lemma (see VACUITY_LEMMAS).  Boolean only.

Classification
  BOOLEAN_MINIMAL        every f has a Boolean witness
  DECISION_MINIMAL_ONLY  every f has a decision witness; each f without a
                         Boolean witness has a Boolean non-necessity certificate
  NOT_MINIMAL            some f has a decision non-necessity certificate
  UNRESOLVED             anything else
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from .canonical import ENUM_TABLES, TypeTag
from .predicates import PREDICATES, Predicate, atom_committed, evaluate, required_fields
from .schema import LAYOUT_V1, REGISTRY

VACUITY_LEMMAS = {
    "amount_defined": "Tariff(mode, price, kWh, durations) >= 0 for all valid-domain inputs: it is a sum of "
                      "products of non-negative quantities (price >= 0, kWh >= 0, durations >= 0, rates >= 0).",
}


def domain_values(name: str, v: Any) -> list[Any]:
    """Alternative values for field ``name`` inside the valid semantic domain."""
    spec = REGISTRY.spec(name)
    t = spec.type_tag
    if t == TypeTag.ENUM:
        return [x for x in ENUM_TABLES[spec.enum_table] if x != v]
    if t == TypeTag.FIXED6:
        return [x for x in (v + Decimal("0.5"), v - Decimal("0.5"), v * 2, Decimal(0), v / 2, Decimal("1000000"))
                if x >= 0 and x != v]
    if t == TypeTag.TIMESTAMP:
        return [v + 3600, v - 3600, v + 10**6, v - 10**6]
    return [str(v) + "_alt", "X"]


def singleton_domain(name: str) -> bool:
    spec = REGISTRY.spec(name)
    return spec.type_tag == TypeTag.ENUM and len(ENUM_TABLES[spec.enum_table]) == 1


def evidence_variants(pred: Predicate, c: dict, ev: dict, rel: dict) -> list[dict]:
    out = [ev]
    res = evaluate(pred, c, ev, rel)
    amt = res.outputs.get("amount")
    if amt is not None:
        out.append({**ev, "effective_limit": max(amt, c["preauth_limit"]), "held_amount": amt})
        out.append({**ev, "effective_limit": c["preauth_limit"], "held_amount": c["preauth_limit"]})
    out.append({**ev, "delivered_kwh": c["cap_kwh"], "available_balance": c["preauth_limit"]})
    out.append({**ev, "ts_start": c["tw_start"], "ts_end": c["tw_end"]})
    return out


def _decision(pred, c, e, rel):
    r = evaluate(pred, c, e, rel)
    return r.ok, (tuple(sorted((k, str(v)) for k, v in r.outputs.items())) if r.ok else ())


def find_witness(pred: Predicate, f: str, c: dict, ev: dict, rel: dict, *, decision: bool) -> dict | None:
    for i, e in enumerate(evidence_variants(pred, c, ev, rel)):
        d1 = _decision(pred, c, e, rel)
        for alt in domain_values(f, c[f]):
            d2 = _decision(pred, {**c, f: alt}, e, rel)
            if (d1 != d2) if decision else (d1[0] != d2[0]):
                return {"c1": str(c[f]), "c2": str(alt), "P_c1": d1[0], "P_c2": d2[0],
                        "out_c1": str(d1[1]), "out_c2": str(d2[1]), "evidence": "base" if i == 0 else f"tightened_{i}"}
    return None


def boolean_nonnecessity(pred: Predicate, f: str) -> str:
    if singleton_domain(f):
        return "SINGLETON_DOMAIN"
    atoms = [a for a in pred.atoms if f in atom_committed(pred, a)]
    if atoms and all(a.label in VACUITY_LEMMAS for a in atoms):
        return "VACUOUS_ATOM:" + ",".join(a.label for a in atoms)
    return ""


@dataclass
class PredicateClass:
    reason: str
    classification: str
    f_r: tuple[str, ...]
    rows: list[dict]


def classify(reason: str, contexts: list[tuple[dict, dict, dict]]) -> PredicateClass:
    """contexts: list of (committed values, evidence, relations) from real sessions."""
    pred = PREDICATES[reason]
    f_r = required_fields(LAYOUT_V1, reason)
    rows = []
    for f in f_r:
        bw = dw = None
        for c, ev, rel in contexts:
            bw = bw or find_witness(pred, f, c, ev, rel, decision=False)
            dw = dw or bw or find_witness(pred, f, c, ev, rel, decision=True)
            if bw:
                break
        bnn = "" if bw else boolean_nonnecessity(pred, f)
        dnn = "SINGLETON_DOMAIN" if (not dw and singleton_domain(f)) else ""
        rows.append({"reason": reason, "field": f, "boolean_witness": bool(bw), "decision_witness": bool(dw),
                     "boolean_nonnecessity_certificate": bnn, "decision_nonnecessity_certificate": dnn,
                     **{f"witness_{k}": v for k, v in (dw or {}).items()}})
    if all(r["boolean_witness"] for r in rows):
        cls = "BOOLEAN_MINIMAL"
    elif any(r["decision_nonnecessity_certificate"] for r in rows):
        cls = "NOT_MINIMAL"
    elif all(r["decision_witness"] for r in rows) and all(
            r["boolean_witness"] or r["boolean_nonnecessity_certificate"] for r in rows):
        cls = "DECISION_MINIMAL_ONLY"
    else:
        cls = "UNRESOLVED"
    return PredicateClass(reason, cls, f_r, rows)


def session_context(env, sess) -> tuple[dict, dict, dict]:
    """(committed values, evidence, relations) of a real session at RECEIPT_SUBMITTED."""
    rec = env.ledger.records[sess.spec.tid]
    r, pv = sess.receipt, sess.private_values
    c = dict(sess.commitment.values)
    ev = {
        "receipt_tid": r["receipt_tid"], "receipt_station_id": r["receipt_station_id"],
        "receipt_meter_id": r["receipt_meter_id"], "applied_tariff_id": r["applied_tariff_id"],
        "applied_tariff_version": r["applied_tariff_version"], "delivered_kwh": r["delivered_kwh"],
        "ts_start": r["ts_start"], "ts_end": r["ts_end"], "sid": r["sid"], "dr_digest": r.dr_digest,
        "connection_duration_s": pv["connection_duration_s"],
        "active_charging_duration_s": pv["active_charging_duration_s"],
        "parking_duration_s": pv["parking_duration_s"], "settlement_currency": rec.currency,
        "effective_limit": rec.effective_limit, "held_amount": rec.held,
        "payee": env.registry.station_beneficiary[r["receipt_station_id"]], "ledger_paytok": rec.paytok,
        "request_tid": c["tid"], "request_user_id": c["user_id"], "request_user_account": c["user_account"],
        "request_paytok": c["paytok"], "available_balance": c["preauth_limit"] + Decimal(100),
    }
    rel = dict(env.registry.relations())
    rel["fresh_receipt"] = lambda d: True
    rel["fresh_session"] = lambda t, sid: t == c["tid"] and sid == r["sid"]
    return c, ev, rel
