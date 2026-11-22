"""
PAM-Proof: predicate-complete authenticated openings of the committed layout.

PAM-Proof uses a standard binary Merkle tree (SHA-256) over canonically
encoded fields, with independent authentication paths or a packed multiproof.
On top of Merkle authenticity the verifier adds a predicate-completeness
check: for the verification reason r it recomputes

    F_req = required_fields(L, r)

from the dependency registry and accepts only if

    F_req is a subset of F(opening)    (policy SUPERSET), or
    F(opening) == F_req                (policy EXACT),

AND the supplied (field_id, value) pairs authenticate to rho_t.

Tree layout
-----------
leaf_i   = SHA256(0x00 | schema_digest | i:u16 | encode_field(f_i, v_i))
pad_i    = SHA256(0x02 | schema_digest | i:u16)
node     = SHA256(0x01 | left | right)
rho_t    = tagged_hash("DVAS-EV/root/v1", schema_digest, merkle_root)

Leaf positions are fixed by the layout schema (ordered by field ID), so a
value presented under the wrong field identifier hashes to a different leaf
and fails authentication.  The schema digest binds the layout version.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

from .canonical import EncodingError, decode_value, encode_field, normalize_value, tagged_hash
from .instrumentation import count
from .predicates import required_fields
from .schema import LAYOUT_V1, PRE, REGISTRY, LayoutSchema, check_layout_values, encode_leaf

HASH_LEN = 32


class CompletenessPolicy(str, Enum):
    SUPERSET = "superset"  # F_req subset of F(opening); extra committed fields allowed
    EXACT = "exact"        # F(opening) == F_req


class ProofKind(str, Enum):
    MULTIPROOF = "multiproof"      # packed: shared siblings deduplicated
    INDEPENDENT = "independent"    # one authentication path per opened field


def _h(prefix: bytes, *parts: bytes) -> bytes:
    count("hash")
    h = hashlib.sha256(prefix)
    for p in parts:
        h.update(p)
    return h.digest()


def leaf_hash(schema: LayoutSchema, name: str, value: Any) -> bytes:
    return _h(b"\x00", encode_leaf(schema, name, value))


def pad_hash(schema: LayoutSchema, index: int) -> bytes:
    return _h(b"\x02", schema.digest(), index.to_bytes(2, "big"))


def node_hash(left: bytes, right: bytes) -> bytes:
    return _h(b"\x01", left, right)


def root_from_merkle(schema: LayoutSchema, merkle_root: bytes) -> str:
    return tagged_hash("DVAS-EV/root/v1", schema.digest(), merkle_root).hex()


def _base(n: int) -> int:
    b = 1
    while b < n:
        b <<= 1
    return b


# ---------------------------------------------------------------------------
# Commitment
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Commitment:
    schema: LayoutSchema
    values: dict[str, Any]
    nodes: tuple[bytes, ...]  # heap array, index 1 = merkle root, leaves at [base, 2*base)
    base: int
    rho_t: str

    @property
    def merkle_root(self) -> bytes:
        return self.nodes[1]


def commit(values: Mapping[str, Any], schema: LayoutSchema = LAYOUT_V1) -> Commitment:
    """Commit a pre-service capsule.  Post-service fields are rejected."""
    check_layout_values(schema, values)
    norm = {n: normalize_value(REGISTRY.spec(n), values.get(n)) for n in schema.field_names}
    n = len(schema.field_names)
    base = _base(n)
    nodes: list[bytes] = [b""] * (2 * base)
    for i, name in enumerate(schema.field_names):
        nodes[base + i] = leaf_hash(schema, name, norm[name])
    for i in range(n, base):
        nodes[base + i] = pad_hash(schema, i)
    for idx in range(base - 1, 0, -1):
        nodes[idx] = node_hash(nodes[2 * idx], nodes[2 * idx + 1])
    return Commitment(schema, norm, tuple(nodes), base, root_from_merkle(schema, nodes[1]))


# ---------------------------------------------------------------------------
# Opening object and wire encoding
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PAMOpening:
    schema_id: str
    reason: str
    proof_kind: ProofKind
    fields: tuple[tuple[int, Any], ...]          # (field_id, value), ascending field_id
    helpers: tuple[bytes, ...] = ()              # multiproof helper hashes (deterministic order)
    paths: tuple[tuple[bytes, ...], ...] = ()    # independent paths, aligned with fields

    @property
    def field_ids(self) -> tuple[int, ...]:
        return tuple(fid for fid, _ in self.fields)

    @property
    def field_names(self) -> tuple[str, ...]:
        return tuple(REGISTRY.spec(fid).name for fid, _ in self.fields)

    def values_by_name(self) -> dict[str, Any]:
        return {REGISTRY.spec(fid).name: v for fid, v in self.fields}

    @property
    def sibling_hash_count(self) -> int:
        if self.proof_kind == ProofKind.MULTIPROOF:
            return len(self.helpers)
        return sum(len(p) for p in self.paths)

    def opened_value_bytes(self) -> int:
        """Bytes of the disclosed (field_id, value) encodings."""
        return sum(len(encode_field(REGISTRY.spec(fid), v)) for fid, v in self.fields)

    def proof_bytes(self) -> int:
        """Bytes of authentication material (hashes only; indices are implied by field IDs)."""
        return self.sibling_hash_count * HASH_LEN

    def to_bytes(self) -> bytes:
        sid = self.schema_id.encode("utf-8")
        rsn = self.reason.encode("utf-8")
        out = [b"PAM1", struct.pack(">H", len(sid)), sid, struct.pack(">H", len(rsn)), rsn,
               b"M" if self.proof_kind == ProofKind.MULTIPROOF else b"I",
               struct.pack(">H", len(self.fields))]
        for fid, v in self.fields:
            out.append(encode_field(REGISTRY.spec(fid), v))
        if self.proof_kind == ProofKind.MULTIPROOF:
            out.append(struct.pack(">H", len(self.helpers)))
            out.extend(self.helpers)
        else:
            for p in self.paths:
                out.append(struct.pack(">B", len(p)))
                out.extend(p)
        return b"".join(out)

    @staticmethod
    def from_bytes(data: bytes) -> "PAMOpening":
        try:
            if data[:4] != b"PAM1":
                raise EncodingError("bad opening magic")
            off = 4
            (ln,) = struct.unpack(">H", data[off:off + 2]); off += 2
            schema_id = data[off:off + ln].decode("utf-8"); off += ln
            (ln,) = struct.unpack(">H", data[off:off + 2]); off += 2
            reason = data[off:off + ln].decode("utf-8"); off += ln
            kind = ProofKind.MULTIPROOF if data[off:off + 1] == b"M" else ProofKind.INDEPENDENT
            off += 1
            (nf,) = struct.unpack(">H", data[off:off + 2]); off += 2
            fields = []
            for _ in range(nf):
                fid, tag, pl = struct.unpack(">HBI", data[off:off + 7]); off += 7
                payload = data[off:off + pl]
                if len(payload) != pl:
                    raise EncodingError("truncated field payload")
                off += pl
                fields.append((fid, decode_value(REGISTRY.spec(fid), tag, payload)))
            helpers: list[bytes] = []
            paths: list[tuple[bytes, ...]] = []
            if kind == ProofKind.MULTIPROOF:
                (nh,) = struct.unpack(">H", data[off:off + 2]); off += 2
                for _ in range(nh):
                    helpers.append(data[off:off + HASH_LEN]); off += HASH_LEN
            else:
                for _ in range(nf):
                    (pl,) = struct.unpack(">B", data[off:off + 1]); off += 1
                    paths.append(tuple(data[off + i * HASH_LEN: off + (i + 1) * HASH_LEN] for i in range(pl)))
                    off += pl * HASH_LEN
            if off != len(data):
                raise EncodingError("trailing bytes in opening")
            return PAMOpening(schema_id, reason, kind, tuple(fields), tuple(helpers), tuple(paths))
        except struct.error as exc:
            raise EncodingError(f"malformed opening: {exc}") from exc


# ---------------------------------------------------------------------------
# Opening generation
# ---------------------------------------------------------------------------

def multiproof_helper_indices(leaf_positions: Iterable[int], base: int) -> list[int]:
    """Generalised indices of helper nodes, in deterministic (descending) order."""
    known = {base + p for p in leaf_positions}
    helpers: set[int] = set()
    level = set(known)
    while level and level != {1}:
        parents = set()
        for idx in level:
            sib = idx ^ 1
            if sib not in level and sib not in known:
                helpers.add(sib)
            parents.add(idx >> 1)
        known |= parents
        level = parents
    return sorted(helpers, reverse=True)


def open_fields(
    commitment: Commitment,
    field_names: Iterable[str],
    *,
    reason: str,
    proof_kind: ProofKind = ProofKind.MULTIPROOF,
) -> PAMOpening:
    count("proof_gen")
    schema = commitment.schema
    names = sorted(set(field_names), key=lambda n: REGISTRY.spec(n).field_id)
    fields = tuple((REGISTRY.spec(n).field_id, commitment.values[n]) for n in names)
    positions = [schema.index_of(n) for n in names]
    if proof_kind == ProofKind.MULTIPROOF:
        idxs = multiproof_helper_indices(positions, commitment.base)
        helpers = tuple(commitment.nodes[i] for i in idxs)
        return PAMOpening(schema.schema_id, reason, proof_kind, fields, helpers=helpers)
    paths = []
    for p in positions:
        idx = commitment.base + p
        path = []
        while idx > 1:
            path.append(commitment.nodes[idx ^ 1])
            idx >>= 1
        paths.append(tuple(path))
    return PAMOpening(schema.schema_id, reason, proof_kind, fields, paths=tuple(paths))


def open_for_reason(
    commitment: Commitment,
    reason: str,
    *,
    proof_kind: ProofKind = ProofKind.MULTIPROOF,
    extra_fields: Sequence[str] = (),
) -> PAMOpening:
    req = required_fields(commitment.schema, reason)
    return open_fields(commitment, list(req) + list(extra_fields), reason=reason, proof_kind=proof_kind)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PAMVerifyResult:
    ok: bool
    code: str
    detail: str = ""
    values: dict[str, Any] = field(default_factory=dict)
    required: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.ok


def _fail(code: str, detail: str = "", **kw: Any) -> PAMVerifyResult:
    return PAMVerifyResult(False, code, detail, **kw)


def verify_opening(
    rho_t: str,
    opening: PAMOpening,
    *,
    reason: str,
    policy: CompletenessPolicy = CompletenessPolicy.SUPERSET,
    check_completeness: bool = True,
    schema: LayoutSchema = LAYOUT_V1,
) -> PAMVerifyResult:
    """Verify predicate completeness (A) and Merkle authenticity (B).

    ``check_completeness=False`` gives an ordinary multiproof verifier
    (used only as the B2 ablation baseline).
    """
    count("proof_verify")
    if opening.schema_id != schema.schema_id:
        return _fail("SCHEMA_MISMATCH", f"{opening.schema_id} != {schema.schema_id}")
    if opening.reason != reason:
        return _fail("REASON_MISMATCH", f"opening for {opening.reason!r}, verifier expects {reason!r}")

    # Structural checks: known, committed-phase, unique, ascending, encodable.
    seen: set[int] = set()
    prev = -1
    positions: list[int] = []
    leaves: list[bytes] = []
    values: dict[str, Any] = {}
    for fid, value in opening.fields:
        try:
            spec = REGISTRY.spec(fid)
        except EncodingError:
            return _fail("UNKNOWN_FIELD", f"0x{fid:04x}")
        if spec.lifecycle != PRE or spec.name not in schema.field_names:
            return _fail("WRONG_PHASE_FIELD", f"{spec.name} is {spec.lifecycle.name}, not a committed layout field")
        if fid in seen:
            return _fail("DUPLICATE_FIELD", spec.name)
        if fid <= prev:
            return _fail("NON_CANONICAL_ORDER", spec.name)
        seen.add(fid)
        prev = fid
        try:
            leaves.append(leaf_hash(schema, spec.name, value))
            values[spec.name] = normalize_value(spec, value)
        except EncodingError as exc:
            return _fail("ENCODING_ERROR", f"{spec.name}: {exc}")
        positions.append(schema.index_of(spec.name))

    # (A) predicate completeness.
    req: tuple[str, ...] = ()
    if check_completeness:
        try:
            req = required_fields(schema, reason)
        except KeyError:
            return _fail("UNKNOWN_REASON", reason)
        opened = set(values)
        missing = tuple(n for n in req if n not in opened)
        if missing:
            return _fail("INCOMPLETE_OPENING", ",".join(missing), required=req, missing=missing)
        if policy == CompletenessPolicy.EXACT and opened != set(req):
            extra = sorted(opened - set(req))
            return _fail("NON_EXACT_OPENING", ",".join(extra), required=req)

    # (B) Merkle authenticity.
    base = _base(len(schema.field_names))
    try:
        if opening.proof_kind == ProofKind.MULTIPROOF:
            root = _root_from_multiproof(positions, leaves, opening.helpers, base)
        else:
            root = _root_from_paths(positions, leaves, opening.paths, base)
    except ValueError as exc:
        return _fail("MALFORMED_PROOF", str(exc))
    if root_from_merkle(schema, root) != rho_t:
        return _fail("ROOT_MISMATCH", "opening does not authenticate to rho_t")
    return PAMVerifyResult(True, "OK", values=values, required=req)


def _root_from_multiproof(positions: list[int], leaves: list[bytes], helpers: Sequence[bytes], base: int) -> bytes:
    if not positions:
        raise ValueError("empty opening")
    idxs = multiproof_helper_indices(positions, base)
    if len(idxs) != len(helpers):
        raise ValueError(f"expected {len(idxs)} helper hashes, got {len(helpers)}")
    known: dict[int, bytes] = {base + p: h for p, h in zip(positions, leaves)}
    for i, h in zip(idxs, helpers):
        if len(h) != HASH_LEN:
            raise ValueError("helper hash length")
        known[i] = h
    for idx in range(base - 1, 0, -1):
        l, r = known.get(2 * idx), known.get(2 * idx + 1)
        if l is not None and r is not None:
            known[idx] = node_hash(l, r)
    if 1 not in known:
        raise ValueError("multiproof does not reach the root")
    return known[1]


def _root_from_paths(positions: list[int], leaves: list[bytes], paths: Sequence[Sequence[bytes]], base: int) -> bytes:
    if not positions or len(paths) != len(positions):
        raise ValueError("one authentication path per opened field required")
    depth = base.bit_length() - 1
    root: bytes | None = None
    for p, leaf, path in zip(positions, leaves, paths):
        if len(path) != depth:
            raise ValueError("path length")
        idx = base + p
        cur = leaf
        for sib in path:
            cur = node_hash(cur, sib) if idx % 2 == 0 else node_hash(sib, cur)
            idx >>= 1
        if root is None:
            root = cur
        elif cur != root:
            return b"\x00" * HASH_LEN  # inconsistent paths -> cannot match rho_t
    assert root is not None
    return root
