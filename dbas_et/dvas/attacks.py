"""
Adversarial test generators.

Families
  A  single-field attacks
  B  compound attacks
  C  sequence / state attacks
Generation
  systematic  every attack on every selected workload row
  randomized  attack parameters (which field, which value, how much) drawn
              from ``random.Random(seed)``.  The seed controls test-case
              selection and mutation parameters only; cryptographic keys
              come from the OS CSPRNG.

Adversary model.  Semantic attacks (wrong pricing/time/cap/station) use a
receipt that the registered meter honestly signs: the meter attests what
physically happened, and the protocol must refuse to settle a delivery that
violates the committed terms.  In-transit attacks (tampered proof, private
payload, RBC) are performed by a party without meter/verifier keys.  A
"successful" attack means the ledger reached SETTLED with the adversarial
content (for the malicious-verifier case: settled with an amount different
from the honest tariff amount).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, replace
from decimal import Decimal
from typing import Any, Callable

from .delivery import private_payload_bytes, resign
from .evidence import seal_evidence
from .ledger import TxState
from .pam import ProofKind, open_fields, open_for_reason
from .predicates import required_fields
from .protocol import DvasEnvironment, Session
from .rbc import QuorumRBC, RBCBody, VerificationAttestation, attestation_message
from .schema import LAYOUT_V1, REGISTRY
from .workload import SessionSpec
from .workload import honest_amount as _exact_amount


@dataclass
class AttackResult:
    attack_id: str
    family: str
    attack: str
    generation: str
    compound: bool
    mutated: str
    expected: str
    actual: str
    stage: str
    reason: str
    row_index: int
    seed: int | None = None
    params: str = ""

    @property
    def unexpected_accept(self) -> bool:
        return self.expected == "REJECT" and self.actual == "ACCEPTED"


def unique(spec: SessionSpec, tag: str) -> SessionSpec:
    return replace(spec, tid=f"{spec.tid}#{tag}", nonce_u=f"{spec.nonce_u}#{tag}", nonce_s=f"{spec.nonce_s}#{tag}")


def _prep(env: DvasEnvironment, spec: SessionSpec, *, deliver: bool = True, **deliver_kw: Any) -> Session:
    s = env.session(spec)
    s.commit()
    r = s.authorize()
    if not r.ok:
        raise RuntimeError(f"setup authorize failed: {r.code} {r.detail}")
    r = s.open_session()
    if not r.ok:
        raise RuntimeError(f"setup session failed: {r.code}")
    if deliver:
        s.deliver(**deliver_kw)
    return s


def _finish(s: Session, *, submit: bool = True, opening=None) -> tuple[str, str]:
    """Run the rest of the pipeline; return (stage, reason) of the first rejection or ('settled','OK')."""
    if submit:
        r = s.submit_receipt()
        if not r.ok:
            return "ledger_submit", r.code
    s.verify(s.settlement_request(opening) if opening is not None else None)
    rbc = s.aggregate()
    if rbc is None:
        reasons = sorted({o.reason for o in s.outcomes if not o.ok})
        return "verifier_quorum", "NO_QUORUM:" + "|".join(reasons)
    r = s.settle(rbc)
    return ("settled", "OK") if r.ok else ("ledger_settle", r.code)


def _settled(env: DvasEnvironment, tid: str) -> bool:
    rec = env.ledger.records.get(tid)
    return bool(rec and rec.state == TxState.SETTLED)


def _att(env: DvasEnvironment, vid: str, body: RBCBody) -> VerificationAttestation:
    n = env.verifiers[vid]
    sig = n.signer.sign(attestation_message(vid, n.key_epoch, body.digest))
    return VerificationAttestation.for_body(body, vid, n.key_epoch, sig, n.signer.scheme)


def _other_station_meter(env: DvasEnvironment, spec: SessionSpec, pool: list[SessionSpec]) -> SessionSpec:
    for p in pool:
        if p.station_id != spec.station_id and p.meter_id != spec.meter_id:
            env.register_spec(p)
            return p
    raise RuntimeError("no alternative station in pool")


# ---------------------------------------------------------------------------
# Attack implementations: fn(env, spec, pool, rng) -> (stage, reason, mutated, params, accepted_override)
# ---------------------------------------------------------------------------

AttackFn = Callable[[DvasEnvironment, SessionSpec, list, random.Random], tuple]


def a_wrong_tid(env, spec, pool, rng):
    other = _prep(env, unique(spec, "victim"), deliver=False)
    s = _prep(env, spec)
    s.receipt = resign(s.receipt.with_values(receipt_tid=other.spec.tid), s.meter.signer)
    stage, reason = _finish(s)
    return stage, reason, "DR_t.receipt_tid", "", _settled(env, other.spec.tid)


def a_wrong_sid(env, spec, pool, rng):
    s = _prep(env, spec)
    s.receipt = resign(s.receipt.with_values(sid="sid-forged-" + s.sid[:8]), s.meter.signer)
    return (*_finish(s), "DR_t.sid", "", None)


def a_wrong_rho(env, spec, pool, rng):
    other = _prep(env, unique(spec, "other-root"), deliver=False)
    s = _prep(env, spec)
    s.receipt = resign(s.receipt.with_values(rho_t=other.commitment.rho_t), s.meter.signer)
    return (*_finish(s), "DR_t.rho_t", "", None)


def a_wrong_station(env, spec, pool, rng):
    alt = _other_station_meter(env, spec, pool)
    s = _prep(env, spec)
    s.receipt = resign(s.receipt.with_values(receipt_station_id=alt.station_id), s.meter.signer)
    return (*_finish(s), "DR_t.receipt_station_id", alt.station_id, None)


def a_wrong_meter(env, spec, pool, rng):
    alt = _other_station_meter(env, spec, pool)
    s = _prep(env, spec, meter=env.meters[alt.meter_id])
    return (*_finish(s), "DR_t signed by another station's registered meter", alt.meter_id, None)


def a_wrong_pricing(env, spec, pool, rng):
    s = _prep(env, spec, applied_tariff_id=spec.tariff_id + "_OTHER")
    return (*_finish(s), "DR_t.applied_tariff_id (meter-signed)", "", None)


def a_wrong_time(env, spec, pool, rng):
    shift = rng.randint(1, 86400) if rng else 3600
    s = _prep(env, spec, ts_end=spec.tw_end + shift)
    return (*_finish(s), "DR_t.ts_end > tw_end (meter-signed)", f"shift_s={shift}", None)


def a_over_cap(env, spec, pool, rng):
    extra = Decimal(str(round(rng.uniform(0.001, 50), 6))) if rng else Decimal("1")
    s = _prep(env, spec, delivered_kwh=spec.cap_kwh + extra)
    return (*_finish(s), "DR_t.delivered_kwh > cap_kwh (meter-signed)", f"extra_kwh={extra}", None)


def a_invalid_amount(env, spec, pool, rng):
    s = _prep(env, spec)
    assert s.submit_receipt().ok
    s.verify()
    honest = [o for o in s.outcomes if o.ok]
    body = honest[0].body
    held = env.ledger.records[spec.tid].held
    bump = Decimal(str(round(rng.uniform(0.000001, float(held - body.captured) or 0.000001), 6))) if rng else Decimal("0.01")
    cap = min(body.captured + bump, held)
    if cap == body.captured:  # no headroom above the honest amount: deflate instead
        cap = body.captured - Decimal("0.000001")
    forged = RBCBody.build(**{**body.values, "captured_amount": cap, "refund_amount": held - cap})
    rbc = QuorumRBC(forged, tuple(o.attestation for o in honest))  # honest signatures over the honest digest
    r = env.ledger.settle(rbc)
    return ("ledger_settle", r.code if not r.ok else "OK", "RBC_body.captured_amount", f"bump={bump}", None)


def a_replay(env, spec, pool, rng):
    s = _prep(env, spec)
    stage, reason = _finish(s)
    assert stage == "settled", (stage, reason)
    r1 = env.ledger.settle(s.rbc)
    r2 = env.ledger.submit_receipt(s.receipt)
    ok = r1.ok or r2.ok
    return ("ledger_settle+submit", f"{r1.code}|{r2.code}", "replayed RBC and receipt", "", ok)


def a_wrong_private_digest(env, spec, pool, rng):
    s = _prep(env, spec)
    forged = dict(s.private_values, session_ref="forged-" + str(rng.random() if rng else 0))
    s.envelope = seal_evidence(private_payload_bytes(forged), s.envelope.context, env.recipients())
    return (*_finish(s), "DR_private substituted in a fresh valid KEM/AEAD envelope", "", None)


def a_missing_required_field(env, spec, pool, rng):
    req = list(required_fields(LAYOUT_V1, "settlement"))
    omit = rng.choice(req) if rng else "cap_kwh"
    s = _prep(env, spec)
    op = open_fields(s.commitment, [n for n in req if n != omit], reason="settlement")
    return (*_finish(s, opening=op), f"S-opening omits {omit} (authentic multiproof)", f"omit={omit}", None)


def a_invalid_proof(env, spec, pool, rng):
    s = _prep(env, spec)
    op = open_for_reason(s.commitment, "settlement")
    i = rng.randrange(len(op.helpers)) if rng else 0
    h = bytearray(op.helpers[i]); h[rng.randrange(32) if rng else 0] ^= 0x01
    bad = replace(op, helpers=op.helpers[:i] + (bytes(h),) + op.helpers[i + 1:])
    return (*_finish(s, opening=bad), "S-opening helper hash bit flip", f"helper={i}", None)


def b_wrong_meter_valid_receipt(env, spec, pool, rng):
    alt = _other_station_meter(env, spec, pool)
    s = _prep(env, spec)
    m = env.meters[alt.meter_id]
    s.receipt = resign(s.receipt.with_values(receipt_meter_id=alt.meter_id, meter_key_epoch=m.key_epoch), m.signer)
    return (*_finish(s), "receipt claims this station but signed by another registered meter", alt.meter_id, None)


def b_tariff_mismatch_authentic_opening(env, spec, pool, rng):
    s = _prep(env, spec, applied_tariff_version=spec.tariff_version + "-x")
    op = open_for_reason(s.commitment, "settlement", proof_kind=ProofKind.MULTIPROOF)
    return (*_finish(s, opening=op), "applied tariff version differs; complete authentic opening", "", None)


def b_stale_receipt_current_tx(env, spec, pool, rng):
    old = _prep(env, unique(spec, "earlier"))
    st, _ = _finish(old)
    assert st == "settled"
    cur = _prep(env, spec)
    cur.receipt = old.receipt  # stale but genuinely signed receipt
    r = env.ledger.submit_receipt(old.receipt.with_values(receipt_tid=spec.tid))
    stage, reason = _finish(cur)
    return stage, f"{reason}|relabel:{r.code}", "earlier settled receipt presented for current tx", "", _settled(env, spec.tid)


def b_missing_operand_overcap(env, spec, pool, rng):
    """The legacy P1 case: over-cap delivery with cap_kwh omitted from an authentic opening."""
    s = _prep(env, spec, delivered_kwh=spec.cap_kwh + Decimal("2"))
    req = required_fields(LAYOUT_V1, "settlement")
    op = open_fields(s.commitment, [n for n in req if n != "cap_kwh"], reason="settlement")
    return (*_finish(s, opening=op), "over-cap + cap_kwh omitted from authentic multiproof", "", None)


def b_malicious_verifier_inflated(env, spec, pool, rng):
    env.verifiers["SV2"].behavior = "inflate"
    try:
        s = _prep(env, spec)
        stage, reason = _finish(s)
    finally:
        env.verifiers["SV2"].behavior = "honest"
    rec = env.ledger.records[spec.tid]
    honest_amount = _exact_amount(spec)
    accepted = rec.state == TxState.SETTLED and rec.captured != honest_amount
    if not accepted and stage == "settled":
        stage, reason = "rbc_aggregation", "MALICIOUS_ATTESTATION_EXCLUDED:honest_2_of_3_settled_correct_amount"
    return stage, reason, "SV2 signs captured=held", f"settled_amount={rec.captured};honest={honest_amount}", accepted


def b_revoked_verifier_valid_signature(env, spec, pool, rng):
    """Uses a private environment so revocation does not shrink the shared cluster."""
    env2 = DvasEnvironment(profile=env.profile, behaviors={"SV2": "offline"})
    env2.register_spec(spec)
    s = _prep(env2, spec)
    assert s.submit_receipt().ok
    s.verify()
    body = s.outcomes[0].body
    env2.registry.revoke("SV3")
    body2 = RBCBody.build(**{**body.values, "verifier_set_epoch": env2.registry.verifier_set_epoch})
    rbc = QuorumRBC(body2, (_att(env2, "SV1", body2), _att(env2, "SV3", body2)))
    r = env2.ledger.settle(rbc)
    return "ledger_settle", r.code if not r.ok else "OK", "revoked SV3 (valid signature) + SV1, SV2 offline", "", r.ok


def b_mixed_roots(env, spec, pool, rng):
    a = _prep(env, spec)
    b = _prep(env, unique(spec, "mix"))
    assert a.submit_receipt().ok and b.submit_receipt().ok
    a.verify(); b.verify()
    rbc = QuorumRBC(a.outcomes[0].body, (a.outcomes[0].attestation, b.outcomes[1].attestation))
    r = env.ledger.settle(rbc)
    return "ledger_settle", r.code if not r.ok else "OK", "attestations from two transaction roots", "", None


def c_settle_before_receipt(env, spec, pool, rng):
    donor = _prep(env, unique(spec, "donor"))
    assert donor.submit_receipt().ok
    donor.verify()
    s = _prep(env, spec, deliver=False)
    b = donor.outcomes[0].body
    forged = RBCBody.build(**{**b.values, "settle_tid": spec.tid, "settle_sid": s.sid,
                              "settle_rho_t": s.commitment.rho_t, "auth_digest": env.ledger.auth_digest(spec.tid)})
    r = env.ledger.settle(QuorumRBC(forged, (_att(env, "SV1", forged), _att(env, "SV2", forged))))
    return "ledger_settle", r.code if not r.ok else "OK", "quorum RBC before any receipt", "", None


def c_settle_before_quorum(env, spec, pool, rng):
    s = _prep(env, spec)
    assert s.submit_receipt().ok
    s.verify()
    r = env.ledger.settle(QuorumRBC(s.outcomes[0].body, (s.outcomes[0].attestation,)))
    return "ledger_settle", r.code if not r.ok else "OK", "single attestation", "", None


def c_duplicate_settlement(env, spec, pool, rng):
    s = _prep(env, spec)
    assert _finish(s)[0] == "settled"
    alt = QuorumRBC(s.rbc.body, tuple(reversed(s.rbc.attestations)))
    r = env.ledger.settle(alt)
    return "ledger_settle", r.code if not r.ok else "OK", "second settlement of same tx", "", r.ok


def c_topup_after_settled(env, spec, pool, rng):
    s = _prep(env, spec)
    assert _finish(s)[0] == "settled"
    r = s.topup(Decimal("1"))
    return "ledger_topup", r.code if not r.ok else "OK", "top-up after SETTLED", "", r.ok


def c_cross_session_receipt_reuse(env, spec, pool, rng):
    a = _prep(env, spec)
    b = _prep(env, unique(spec, "xs"), deliver=False)
    r = env.ledger.submit_receipt(a.receipt.with_values(receipt_tid=b.spec.tid, sid=b.sid))
    return "ledger_submit", r.code if not r.ok else "OK", "receipt of session A submitted for session B", "", r.ok


def c_cross_root_rbc_reuse(env, spec, pool, rng):
    a = _prep(env, unique(spec, "xr"))
    assert _finish(a)[0] == "settled"
    b = _prep(env, spec)
    assert b.submit_receipt().ok
    relabel = replace(a.rbc.body, values={**a.rbc.body.values, "settle_tid": spec.tid})
    r = env.ledger.settle(QuorumRBC(relabel, a.rbc.attestations))
    return "ledger_settle", r.code if not r.ok else "OK", "settled RBC of tx A re-targeted at tx B", "", r.ok


def r_compound(env, spec, pool, rng):
    """Randomized compound: one semantic violation AND one proof/evidence manipulation."""
    sem = rng.choice(["over_cap", "wrong_time", "wrong_pricing", "none"])
    man = rng.choice(["omit_field", "flip_helper", "substitute_private"] + (["none"] if sem != "none" else []))
    kw: dict[str, Any] = {}
    if sem == "over_cap":
        kw["delivered_kwh"] = spec.cap_kwh + Decimal(str(round(rng.uniform(0.001, 20), 6)))
    elif sem == "wrong_time":
        kw["ts_start"] = spec.tw_start - rng.randint(1, 7200)
    elif sem == "wrong_pricing":
        kw["applied_tariff_version"] = spec.tariff_version + "-alt"
    s = _prep(env, spec, **kw)
    req = list(required_fields(LAYOUT_V1, "settlement"))
    op = open_for_reason(s.commitment, "settlement")
    detail = ""
    if man == "omit_field":
        omit = rng.choice(req)
        op = open_fields(s.commitment, [n for n in req if n != omit], reason="settlement")
        detail = f"omit={omit}"
    elif man == "flip_helper":
        i = rng.randrange(len(op.helpers))
        h = bytearray(op.helpers[i]); h[rng.randrange(32)] ^= 1
        op = replace(op, helpers=op.helpers[:i] + (bytes(h),) + op.helpers[i + 1:])
        detail = f"helper={i}"
    elif man == "substitute_private":
        forged = dict(s.private_values, session_ref="forged")
        s.envelope = seal_evidence(private_payload_bytes(forged), s.envelope.context, env.recipients())
    return (*_finish(s, opening=op), f"semantic={sem}+manipulation={man}", detail, None)


ATTACKS: dict[str, tuple[str, bool, AttackFn]] = {
    # family A
    "wrong_tid": ("A", False, a_wrong_tid),
    "wrong_sid": ("A", False, a_wrong_sid),
    "wrong_rho": ("A", False, a_wrong_rho),
    "wrong_station": ("A", False, a_wrong_station),
    "wrong_meter": ("A", False, a_wrong_meter),
    "wrong_pricing": ("A", False, a_wrong_pricing),
    "wrong_time": ("A", False, a_wrong_time),
    "over_cap": ("A", False, a_over_cap),
    "invalid_amount": ("A", False, a_invalid_amount),
    "replay": ("A", False, a_replay),
    "wrong_private_digest": ("A", False, a_wrong_private_digest),
    "missing_required_field": ("A", False, a_missing_required_field),
    "invalid_proof": ("A", False, a_invalid_proof),
    # family B
    "wrong_meter_valid_receipt": ("B", True, b_wrong_meter_valid_receipt),
    "tariff_mismatch_authentic_opening": ("B", True, b_tariff_mismatch_authentic_opening),
    "stale_receipt_current_tx": ("B", True, b_stale_receipt_current_tx),
    "missing_operand_valid_multiproof_overcap": ("B", True, b_missing_operand_overcap),
    "malicious_verifier_incorrect_decision": ("B", True, b_malicious_verifier_inflated),
    "revoked_verifier_valid_signature": ("B", True, b_revoked_verifier_valid_signature),
    "mixed_attestations_different_roots": ("B", True, b_mixed_roots),
    "randomized_compound": ("B", True, r_compound),
    # family C
    "settle_before_receipt": ("C", False, c_settle_before_receipt),
    "settle_before_quorum": ("C", False, c_settle_before_quorum),
    "duplicate_settlement": ("C", False, c_duplicate_settlement),
    "topup_after_settled": ("C", False, c_topup_after_settled),
    "cross_session_receipt_reuse": ("C", False, c_cross_session_receipt_reuse),
    "cross_root_rbc_reuse": ("C", False, c_cross_root_rbc_reuse),
}

RANDOMIZABLE = ["wrong_time", "over_cap", "invalid_amount", "wrong_private_digest", "missing_required_field",
                "invalid_proof", "randomized_compound"]
SYSTEMATIC = [a for a in ATTACKS if a != "randomized_compound"]


def run_attack(env: DvasEnvironment, name: str, spec: SessionSpec, pool: list[SessionSpec], *,
               generation: str = "systematic", rng: random.Random | None = None, seed: int | None = None,
               case_no: int = 0) -> AttackResult:
    family, compound, fn = ATTACKS[name]
    sp = unique(spec, f"{name}:{generation}:{case_no}")
    env.register_spec(sp)
    try:
        stage, reason, mutated, params, accepted = fn(env, sp, pool, rng)
        if accepted is None:
            accepted = _settled(env, sp.tid) and stage == "settled"
        actual = "ACCEPTED" if accepted else "REJECTED"
    except Exception as exc:  # harness/setup failure is reported, never counted as a rejection
        stage, reason, mutated, params, actual = "harness", f"{type(exc).__name__}:{exc}", "", "", "ERROR"
    return AttackResult(f"{name}:{generation}:{spec.row_index}:{case_no}", family, name, generation, compound,
                        mutated, "REJECT", actual, stage, reason, spec.row_index, seed, params)
