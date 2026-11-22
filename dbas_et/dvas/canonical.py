"""
Deterministic canonical encoding for DVAS-EV (encoding version 1).

Every party that hashes a transaction object, computes a Merkle leaf, signs a
receipt, or signs a settlement decision uses this encoder.  The encoding is a
binary type-length-value format. JSON is never hashed directly.

Wire format
-----------
record  := MAGIC(7)="DVAS-EV" | enc_version:u8 | record_type:u16 | n_fields:u16
           | field*                      (fields strictly ascending by field_id)
field   := field_id:u16 | type_tag:u8 | length:u32 | payload

All integers are big-endian.  Payload per type tag:

UINT      0x01  u64 (rejects negative, bool, > 2^64-1)
INT       0x02  two's-complement i64 (rejects bool)
FIXED6    0x03  i64 count of 10^-6 units.  Energy is kWh with six decimals
                (1 unit = 1 mWh). Money is currency units with six decimals.
                Input must already be exactly representable at 6 decimals
                (normalisation happens explicitly via ``to_fixed6``).
STRING    0x04  UTF-8 bytes of an NFC-normalised string (non-NFC input is
                rejected, not silently normalised)
BYTES     0x05  raw bytes
ENUM      0x06  u16 code from a registered enum table
TIMESTAMP 0x07  i64 Unix seconds, UTC.  Accepts int or tz-aware datetime,
                rejects naive datetimes and strings.
BOOL      0x08  one byte 0x00/0x01 (only real bool accepted)
DIGEST32  0x09  exactly 32 bytes (hex string of 64 chars or bytes)
NULL      0x0A  empty payload: value absent for an OPTIONAL field
"""

from __future__ import annotations

import hashlib
import struct
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation
from enum import IntEnum
from typing import Any, Iterable, Mapping

MAGIC = b"DVAS-EV"
ENCODING_VERSION = 1

FIXED6_SCALE = 1_000_000
_FIXED6_QUANT = Decimal("0.000001")
_U64_MAX = (1 << 64) - 1
_I64_MIN = -(1 << 63)
_I64_MAX = (1 << 63) - 1


class EncodingError(ValueError):
    """Raised when a value cannot be canonically encoded or decoded."""


class TypeTag(IntEnum):
    UINT = 0x01
    INT = 0x02
    FIXED6 = 0x03
    STRING = 0x04
    BYTES = 0x05
    ENUM = 0x06
    TIMESTAMP = 0x07
    BOOL = 0x08
    DIGEST32 = 0x09
    NULL = 0x0A


class Lifecycle(IntEnum):
    """When a semantic field comes into existence."""

    PRE_SERVICE_COMMITTED = 1
    POST_SERVICE_EVIDENCE = 2
    SETTLEMENT_OUTPUT = 3


# ---------------------------------------------------------------------------
# Enum tables (stable codes, never renumbered, only appended)
# ---------------------------------------------------------------------------

ENUM_TABLES: dict[str, dict[str, int]] = {
    "tariff_mode": {
        "ENERGY_ONLY": 1,
        "ENERGY_ACTIVE_TIME": 2,
        "ENERGY_ACTIVE_PARKING": 3,
        "CONNECTION_TIME": 4,
    },
    "payment_semantics": {
        "RESERVE_RELEASE": 1,
    },
    "decision": {
        "ACCEPT": 1,
        "REJECT": 2,
    },
}


def enum_code(table: str, value: str) -> int:
    try:
        return ENUM_TABLES[table][value]
    except KeyError as exc:
        raise EncodingError(f"value {value!r} not in enum table {table!r}") from exc


def enum_value(table: str, code: int) -> str:
    for name, c in ENUM_TABLES[table].items():
        if c == code:
            return name
    raise EncodingError(f"code {code} not in enum table {table!r}")


# ---------------------------------------------------------------------------
# Value normalisation helpers (explicit boundary conversions)
# ---------------------------------------------------------------------------

def to_fixed6(value: Any) -> Decimal:
    """Normalise a numeric input to a 6-decimal Decimal (ROUND_HALF_EVEN).

    This is the only place where rounding is allowed.  Capsule builders call
    it once when importing dataset values. The encoder itself is strict.
    """
    if isinstance(value, bool):
        raise EncodingError("bool is not a FIXED6 value")
    if isinstance(value, Decimal):
        d = value
    elif isinstance(value, int):
        d = Decimal(value)
    elif isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise EncodingError("non-finite float")
        d = Decimal(repr(value))
    elif isinstance(value, str):
        try:
            d = Decimal(value.strip())
        except InvalidOperation as exc:
            raise EncodingError(f"invalid decimal string {value!r}") from exc
    else:
        raise EncodingError(f"unsupported FIXED6 input type {type(value).__name__}")
    if not d.is_finite():
        raise EncodingError("non-finite decimal")
    return d.quantize(_FIXED6_QUANT, rounding=ROUND_HALF_EVEN)


def fixed6_units(value: Any) -> int:
    """Strictly convert to integer micro-units. Reject values needing rounding."""
    if isinstance(value, bool):
        raise EncodingError("bool is not a FIXED6 value")
    if isinstance(value, Decimal):
        d = value
    elif isinstance(value, int):
        d = Decimal(value)
    elif isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise EncodingError("non-finite float")
        d = Decimal(repr(value))
    elif isinstance(value, str):
        try:
            d = Decimal(value)
        except InvalidOperation as exc:
            raise EncodingError(f"invalid decimal string {value!r}") from exc
    else:
        raise EncodingError(f"unsupported FIXED6 type {type(value).__name__}")
    scaled = d * FIXED6_SCALE
    if scaled != scaled.to_integral_value():
        raise EncodingError(f"FIXED6 value {value!r} has more than 6 decimals; normalise with to_fixed6 first")
    units = int(scaled)
    if not (_I64_MIN <= units <= _I64_MAX):
        raise EncodingError("FIXED6 out of i64 range")
    return units


def from_fixed6_units(units: int) -> Decimal:
    return (Decimal(units) / FIXED6_SCALE).quantize(_FIXED6_QUANT)


def to_timestamp(value: Any) -> int:
    if isinstance(value, bool):
        raise EncodingError("bool is not a timestamp")
    if isinstance(value, int):
        return value
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise EncodingError("naive datetime is ambiguous; supply a tz-aware datetime")
        return int(value.timestamp())
    raise EncodingError(f"timestamp must be int Unix seconds or tz-aware datetime, got {type(value).__name__}")


def _digest_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        b = bytes(value)
    elif isinstance(value, str):
        if len(value) != 64:
            raise EncodingError("DIGEST32 hex string must have 64 characters")
        try:
            b = bytes.fromhex(value)
        except ValueError as exc:
            raise EncodingError("DIGEST32 is not valid hex") from exc
    else:
        raise EncodingError(f"DIGEST32 must be bytes or hex str, got {type(value).__name__}")
    if len(b) != 32:
        raise EncodingError("DIGEST32 must be exactly 32 bytes")
    return b


# ---------------------------------------------------------------------------
# Field specification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FieldSpec:
    field_id: int
    name: str
    type_tag: TypeTag
    lifecycle: Lifecycle
    group: str = ""
    unit: str = ""
    enum_table: str = ""
    optional: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        if not (0 < self.field_id <= 0xFFFF):
            raise ValueError("field_id must be a non-zero u16")
        if self.type_tag == TypeTag.ENUM and not self.enum_table:
            raise ValueError(f"ENUM field {self.name} requires enum_table")


def encode_value(spec: FieldSpec, value: Any) -> tuple[TypeTag, bytes]:
    """Encode one value according to its spec.  Returns (actual_tag, payload)."""
    if value is None:
        if not spec.optional:
            raise EncodingError(f"field {spec.name} is required")
        return TypeTag.NULL, b""

    t = spec.type_tag
    if t == TypeTag.UINT:
        if isinstance(value, bool) or not isinstance(value, int):
            raise EncodingError(f"{spec.name}: UINT requires int, got {type(value).__name__}")
        if not (0 <= value <= _U64_MAX):
            raise EncodingError(f"{spec.name}: UINT out of range")
        return t, struct.pack(">Q", value)
    if t == TypeTag.INT:
        if isinstance(value, bool) or not isinstance(value, int):
            raise EncodingError(f"{spec.name}: INT requires int, got {type(value).__name__}")
        if not (_I64_MIN <= value <= _I64_MAX):
            raise EncodingError(f"{spec.name}: INT out of range")
        return t, struct.pack(">q", value)
    if t == TypeTag.FIXED6:
        return t, struct.pack(">q", fixed6_units(value))
    if t == TypeTag.STRING:
        if not isinstance(value, str):
            raise EncodingError(f"{spec.name}: STRING requires str, got {type(value).__name__}")
        if unicodedata.normalize("NFC", value) != value:
            raise EncodingError(f"{spec.name}: string is not NFC-normalised")
        return t, value.encode("utf-8")
    if t == TypeTag.BYTES:
        if not isinstance(value, (bytes, bytearray)):
            raise EncodingError(f"{spec.name}: BYTES requires bytes")
        return t, bytes(value)
    if t == TypeTag.ENUM:
        if not isinstance(value, str):
            raise EncodingError(f"{spec.name}: ENUM requires the symbolic str value")
        return t, struct.pack(">H", enum_code(spec.enum_table, value))
    if t == TypeTag.TIMESTAMP:
        return t, struct.pack(">q", to_timestamp(value))
    if t == TypeTag.BOOL:
        if not isinstance(value, bool):
            raise EncodingError(f"{spec.name}: BOOL requires bool")
        return t, b"\x01" if value else b"\x00"
    if t == TypeTag.DIGEST32:
        return t, _digest_bytes(value)
    raise EncodingError(f"unsupported type tag {t}")


def decode_value(spec: FieldSpec, tag: int, payload: bytes) -> Any:
    if tag == TypeTag.NULL:
        if not spec.optional:
            raise EncodingError(f"{spec.name}: NULL for required field")
        if payload:
            raise EncodingError("NULL with payload")
        return None
    if tag != spec.type_tag:
        raise EncodingError(f"{spec.name}: type tag {tag} != expected {int(spec.type_tag)}")
    t = spec.type_tag
    if t == TypeTag.UINT:
        if len(payload) != 8:
            raise EncodingError("UINT length")
        return struct.unpack(">Q", payload)[0]
    if t in (TypeTag.INT, TypeTag.TIMESTAMP):
        if len(payload) != 8:
            raise EncodingError("INT/TIMESTAMP length")
        return struct.unpack(">q", payload)[0]
    if t == TypeTag.FIXED6:
        if len(payload) != 8:
            raise EncodingError("FIXED6 length")
        return from_fixed6_units(struct.unpack(">q", payload)[0])
    if t == TypeTag.STRING:
        s = payload.decode("utf-8")
        if unicodedata.normalize("NFC", s) != s:
            raise EncodingError("decoded string not NFC")
        return s
    if t == TypeTag.BYTES:
        return payload
    if t == TypeTag.ENUM:
        if len(payload) != 2:
            raise EncodingError("ENUM length")
        return enum_value(spec.enum_table, struct.unpack(">H", payload)[0])
    if t == TypeTag.BOOL:
        if payload not in (b"\x00", b"\x01"):
            raise EncodingError("BOOL payload")
        return payload == b"\x01"
    if t == TypeTag.DIGEST32:
        if len(payload) != 32:
            raise EncodingError("DIGEST32 length")
        return payload.hex()
    raise EncodingError(f"unsupported type tag {t}")


def encode_field(spec: FieldSpec, value: Any) -> bytes:
    tag, payload = encode_value(spec, value)
    return struct.pack(">HBI", spec.field_id, int(tag), len(payload)) + payload


def normalize_value(spec: FieldSpec, value: Any) -> Any:
    """Return the canonical Python value (round-trip through encode/decode)."""
    tag, payload = encode_value(spec, value)
    return decode_value(spec, int(tag), payload)


# ---------------------------------------------------------------------------
# Field registry and record types
# ---------------------------------------------------------------------------

class FieldRegistry:
    """Global field registry: stable u16 IDs, names, types and lifecycle."""

    def __init__(self, specs: Iterable[FieldSpec]) -> None:
        self.by_id: dict[int, FieldSpec] = {}
        self.by_name: dict[str, FieldSpec] = {}
        for s in specs:
            if s.field_id in self.by_id:
                raise ValueError(f"duplicate field id 0x{s.field_id:04x}")
            if s.name in self.by_name:
                raise ValueError(f"duplicate field name {s.name}")
            self.by_id[s.field_id] = s
            self.by_name[s.name] = s

    def spec(self, key: int | str) -> FieldSpec:
        try:
            return self.by_id[key] if isinstance(key, int) else self.by_name[key]
        except KeyError as exc:
            raise EncodingError(f"unknown field {key!r}") from exc

    def digest(self) -> bytes:
        """Digest of the whole registry definition (binds the schema version, cached)."""
        cached = getattr(self, "_digest", None)
        if cached is not None:
            return cached
        h = hashlib.sha256(b"DVAS-EV/field-registry/v1")
        for fid in sorted(self.by_id):
            s = self.by_id[fid]
            h.update(struct.pack(">HBB", fid, int(s.type_tag), int(s.lifecycle)))
            h.update(s.name.encode("utf-8") + b"\x00" + s.enum_table.encode("utf-8") + b"\x00")
            h.update(b"\x01" if s.optional else b"\x00")
        self._digest = h.digest()
        return self._digest


@dataclass(frozen=True)
class RecordType:
    type_id: int
    name: str
    field_names: tuple[str, ...]
    allowed_lifecycles: frozenset[Lifecycle] | None = None


def encode_record(
    registry: FieldRegistry,
    rtype: RecordType,
    values: Mapping[str, Any],
) -> bytes:
    """Encode a record.  Every declared field must be supplied (None for optional)."""
    supplied = set(values)
    declared = set(rtype.field_names)
    extra = supplied - declared
    if extra:
        raise EncodingError(f"{rtype.name}: undeclared fields {sorted(extra)}")
    missing = declared - supplied
    if missing:
        raise EncodingError(f"{rtype.name}: missing fields {sorted(missing)}")
    specs = sorted((registry.spec(n) for n in rtype.field_names), key=lambda s: s.field_id)
    out = [MAGIC, struct.pack(">BHH", ENCODING_VERSION, rtype.type_id, len(specs))]
    for s in specs:
        if rtype.allowed_lifecycles is not None and s.lifecycle not in rtype.allowed_lifecycles:
            raise EncodingError(f"{rtype.name}: field {s.name} has lifecycle {s.lifecycle.name} not allowed")
        out.append(encode_field(s, values[s.name]))
    return b"".join(out)


def decode_record(registry: FieldRegistry, rtype: RecordType, data: bytes) -> dict[str, Any]:
    if not data.startswith(MAGIC):
        raise EncodingError("bad magic")
    off = len(MAGIC)
    if len(data) < off + 5:
        raise EncodingError("truncated header")
    version, type_id, n = struct.unpack(">BHH", data[off:off + 5])
    off += 5
    if version != ENCODING_VERSION:
        raise EncodingError(f"encoding version mismatch: {version} != {ENCODING_VERSION}")
    if type_id != rtype.type_id:
        raise EncodingError(f"record type mismatch: {type_id} != {rtype.type_id}")
    expected = sorted(registry.spec(nm).field_id for nm in rtype.field_names)
    if n != len(expected):
        raise EncodingError("field count mismatch")
    out: dict[str, Any] = {}
    prev = -1
    for i in range(n):
        if len(data) < off + 7:
            raise EncodingError("truncated field header")
        fid, tag, ln = struct.unpack(">HBI", data[off:off + 7])
        off += 7
        if fid <= prev:
            raise EncodingError("fields not strictly ascending")
        if fid != expected[i]:
            raise EncodingError(f"unexpected field id 0x{fid:04x}")
        prev = fid
        payload = data[off:off + ln]
        if len(payload) != ln:
            raise EncodingError("truncated payload")
        off += ln
        spec = registry.spec(fid)
        out[spec.name] = decode_value(spec, tag, payload)
    if off != len(data):
        raise EncodingError("trailing bytes")
    return out


def tagged_hash(domain: str, *parts: bytes) -> bytes:
    """SHA-256 with an explicit length-prefixed domain and parts."""
    from .instrumentation import count

    count("hash")
    h = hashlib.sha256()
    d = domain.encode("utf-8")
    h.update(struct.pack(">H", len(d)) + d)
    for p in parts:
        h.update(struct.pack(">I", len(p)) + p)
    return h.digest()


def record_digest(registry: FieldRegistry, rtype: RecordType, values: Mapping[str, Any]) -> str:
    """Hex digest of a canonical record."""
    return tagged_hash(f"DVAS-EV/record/{rtype.name}/v1", encode_record(registry, rtype, values)).hex()
