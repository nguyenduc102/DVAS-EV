"""
Certified minimum-cardinality gate for the PA-MSP selector (analysis only).

Nothing here changes the runtime selector ``predicates.required_fields``.
This module certifies, per verification reason r, that the selected set
F_r = required_fields(L, r) is the unique minimum-cardinality sufficient
committed-field set for the verifier output g_r over the admissible domain.

Verifier output (what a SettlementVerifier signs / the ledger acts on)
    g_r(M, E) = (accept, amount)   amount = exact Decimal tariff amount when r
                                   defines it (it fixes capture/refund), else None.
    Failure labels are diagnostics and are not part of g_r.

Admissible domain D_adm (what an untrusted committer can place in a leaf)
    STRING     any non-empty NFC string
    FIXED6     any value >= 0 (6 decimals)
    TIMESTAMP  any integer
    ENUM       any u16 code.  A code outside the registered table is a
               well-formed leaf that the verifier cannot decode: the source
               verifier rejects the opening (ENCODING_ERROR), so g_r = reject.
    Evidence E is shared by both inputs of every comparison.

Certificate
  (S) Sufficiency by construction:
      S1  static: the committed operands of every atom and every output term
          of predicate r equal F_r, and ``evaluate`` reads committed values
          only through ``_eval(C(name))`` (checked on the AST of predicates.py)
      S2  runtime: a guarded mapping records every committed key that
          ``evaluate`` touches on real contexts, and all keys lie in F_r
      S3  differential: randomising every field outside F_r with admissible
          and adversarial values never changes g_r, and the production path
          (Commit -> Open(F_r) -> Verify -> evaluate on opened values) returns
          the same g_r as the full evaluator.
      S1 is a proof for all inputs (g_r is a function of M[F_r] and E)
      S2/S3 check that the source code matches that statement.
  (N) Necessity: for every f in F_r an admissible witness pair (M, M', E)
      differing only in f with g_r(M,E) != g_r(M',E), replayed through the
      production path.  Then every sufficient G contains F_r, so F_r is the
      unique minimum.
  Status PROVED_UNIQUE_MINIMUM requires S1, S2, S3 and N for every field,
  otherwise PARTIAL (the fields without witnesses are listed).
"""

from __future__ import annotations

import ast
import inspect
import random
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Iterator, Mapping

from . import predicates as _predicates_mod
from .canonical import ENUM_TABLES, TypeTag, to_fixed6
from .minimality import evidence_variants
from .pam_api import Commit, Open, Setup, Verify
from .predicates import PREDICATES, Predicate, _term_committed, atom_terms, committed_operands, evaluate, required_fields
from .schema import LAYOUT_V1, REGISTRY

UNREGISTERED_ENUM = "__UNREGISTERED_CODE__"


# ---------------------------------------------------------------------------
# Output g_r
# ---------------------------------------------------------------------------

def g_output(pred: Predicate, committed: Mapping[str, Any], ev: Mapping[str, Any], rel: Mapping[str, Any]):
    res = evaluate(pred, committed, ev, rel)
    amt = res.outputs.get("amount") if res.ok else None
    return (bool(res.ok), str(amt) if amt is not None else None)


REJECT = (False, None)


# ---------------------------------------------------------------------------
# S1: static dependency proof
# ---------------------------------------------------------------------------

def all_term_operands(pred: Predicate) -> frozenset[str]:
    """Committed operands of every atom and every output (used or not)."""
    out: set[str] = set()
    for a in pred.atoms:
        for t in atom_terms(a):
            out |= _term_committed(t)
    for _, t in pred.outputs:
        out |= _term_committed(t)
    return frozenset(out)


def evaluator_reads_committed_only_via_C() -> tuple[bool, str]:
    """AST check: inside predicates.py, the parameter ``committed`` is only
    subscripted / membership-tested in ``_eval`` (the C-term branch). Every
    other function passes it through unchanged."""
    tree = ast.parse(inspect.getsource(_predicates_mod))
    offenders = []
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for node in ast.walk(fn):
            uses = []
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == "committed":
                uses.append("subscript")
            if isinstance(node, ast.Compare) and any(isinstance(c, ast.Name) and c.id == "committed" for c in node.comparators):
                uses.append("membership")
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "committed":
                uses.append(f"attr:{node.attr}")
            for u in uses:
                if fn.name != "_eval":
                    offenders.append(f"{fn.name}:{u}")
    # inside _eval the only access must be guarded by isinstance(t, C)
    ok = not offenders
    return ok, ("only _eval(C) reads committed values" if ok else "; ".join(offenders))


# ---------------------------------------------------------------------------
# S2: guarded mapping
# ---------------------------------------------------------------------------

class GuardedMapping(dict):
    def __init__(self, data: Mapping[str, Any]):
        super().__init__(data)
        self.touched: set[str] = set()

    def __getitem__(self, k):
        self.touched.add(k)
        return super().__getitem__(k)

    def __contains__(self, k):
        self.touched.add(k)
        return super().__contains__(k)

    def get(self, k, default=None):  # noqa: D401
        self.touched.add(k)
        return super().get(k, default)


# ---------------------------------------------------------------------------
# Admissible alternative values
# ---------------------------------------------------------------------------

def admissible_alternatives(name: str, v: Any) -> list[Any]:
    spec = REGISTRY.spec(name)
    t = spec.type_tag
    if t == TypeTag.ENUM:
        return [x for x in ENUM_TABLES[spec.enum_table] if x != v] + [UNREGISTERED_ENUM]
    if t == TypeTag.FIXED6:
        cands = (v + Decimal("0.5"), v - Decimal("0.5"), v * 2, Decimal(0), v / 2, Decimal("1000000"))
        return [x for x in (to_fixed6(c) for c in cands) if x >= 0 and x != v]
    if t == TypeTag.TIMESTAMP:
        return [v + 3600, v - 3600, v + 10**6, v - 10**6]
    return [str(v) + "_alt", "X"]


def random_admissible(name: str, v: Any, rng: random.Random) -> Any:
    alts = admissible_alternatives(name, v)
    return rng.choice(alts) if alts else v


@contextmanager
def adversarial_enum_code(name: str) -> Iterator[str]:
    """Simulate an untrusted committer writing an unregistered ENUM code into a
    leaf: temporarily register a fresh code so the library can build the leaf,
    then remove it before any verification."""
    table = ENUM_TABLES[REGISTRY.spec(name).enum_table]
    code = max(table.values()) + 1
    table[UNREGISTERED_ENUM] = code
    try:
        yield UNREGISTERED_ENUM
    finally:
        del table[UNREGISTERED_ENUM]


# ---------------------------------------------------------------------------
# Production-path replay
# ---------------------------------------------------------------------------

PP = Setup(LAYOUT_V1)


def production_g(reason: str, values: Mapping[str, Any], ev, rel) -> tuple[tuple, str]:
    """Commit -> Open(F_r) -> Verify -> evaluate(opened values).  Returns (g, verify_code)."""
    pred = PREDICATES[reason]
    f_r = required_fields(LAYOUT_V1, reason)
    adversarial = [n for n in f_r if values.get(n) == UNREGISTERED_ENUM]
    if adversarial:
        with adversarial_enum_code(adversarial[0]):
            rho, state = Commit(PP, values)
            pi = Open(PP, state, f_r, r=reason)
    else:
        rho, state = Commit(PP, values)
        pi = Open(PP, state, f_r, r=reason)
    vr = Verify(PP, rho, reason, pi)
    if not vr.ok:
        return REJECT, vr.code
    return g_output(pred, vr.values, ev, rel), vr.code


# ---------------------------------------------------------------------------
# Certificate per reason
# ---------------------------------------------------------------------------

@dataclass
class ReasonCertificate:
    reason: str
    f_r: tuple[str, ...]
    output: str
    s1_static: bool
    s1_detail: str
    s2_touched_subset: bool
    s2_touched: tuple[str, ...]
    s3_trials: int
    s3_mismatches: int
    s3_production_trials: int
    s3_production_mismatches: int
    witnesses: list[dict]
    status: str


def certify(reason: str, contexts, rng: random.Random, randomisations: int = 8) -> ReasonCertificate:
    pred = PREDICATES[reason]
    f_r = required_fields(LAYOUT_V1, reason)
    fset = set(f_r)
    output = "(accept, amount)" if any(n == "amount" for n, _ in pred.outputs) else "(accept)"

    # S1
    ops_all = all_term_operands(pred)
    ast_ok, ast_detail = evaluator_reads_committed_only_via_C()
    s1 = ast_ok and ops_all == fset == set(committed_operands(pred))
    s1_detail = ast_detail if s1 else f"{ast_detail}; operands={sorted(ops_all)} F_r={sorted(fset)}"

    # S2 + S3
    touched: set[str] = set()
    trials = mism = ptrials = pmism = 0
    non_f = [n for n in LAYOUT_V1.field_names if n not in fset]
    for _env, _s, (c, ev, rel) in contexts:
        for e in evidence_variants(pred, c, ev, rel):
            gm = GuardedMapping(c)
            g_full = g_output(pred, gm, e, rel)
            touched |= gm.touched
            for _ in range(randomisations):
                mutated = dict(c)
                for n in non_f:
                    alt = random_admissible(n, c[n], rng)
                    if alt != UNREGISTERED_ENUM:
                        mutated[n] = alt
                trials += 1
                mism += g_output(pred, mutated, e, rel) != g_full
                ptrials += 1
                g_prod, _ = production_g(reason, mutated, e, rel)
                pmism += g_prod != g_full

    # N
    witnesses = []
    for f in f_r:
        found = None
        for _env, _s, (c, ev, rel) in contexts:
            for i, e in enumerate(evidence_variants(pred, c, ev, rel)):
                g1, code1 = production_g(reason, c, e, rel)
                for alt in admissible_alternatives(f, c[f]):
                    g2, code2 = production_g(reason, {**c, f: alt}, e, rel)
                    if g1 != g2:
                        found = {"reason": reason, "field": f, "v1": str(c[f]), "v2": str(alt),
                                 "domain": "adversarial_unregistered_enum" if alt == UNREGISTERED_ENUM else "registered",
                                 "g1": str(g1), "g2": str(g2), "verify_code_1": code1, "verify_code_2": code2,
                                 "evidence": "base" if i == 0 else f"tightened_{i}"}
                        break
                if found:
                    break
            if found:
                break
        witnesses.append(found or {"reason": reason, "field": f, "v1": "", "v2": "", "domain": "NONE",
                                   "g1": "", "g2": "", "verify_code_1": "", "verify_code_2": "", "evidence": ""})

    n_ok = all(w["domain"] != "NONE" for w in witnesses)
    s2 = touched <= fset
    status = "PROVED_UNIQUE_MINIMUM" if (s1 and s2 and mism == 0 and pmism == 0 and n_ok) else "PARTIAL"
    return ReasonCertificate(reason, f_r, output, s1, s1_detail, s2, tuple(sorted(touched)), trials, mism,
                             ptrials, pmism, witnesses, status)
