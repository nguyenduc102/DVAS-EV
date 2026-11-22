"""JSON wire codec used by the multi-process benchmark.

Only a benchmark transport: crypto messages still use the canonical TLV
encoding. Byte counts are taken from these UTF-8 buffers (plus the 4-byte TCP
frame). TCP workers do not accept pickle, only the type whitelist below.
"""
from __future__ import annotations

import dataclasses
import json
from decimal import Decimal
from enum import Enum
from typing import Any

from .delivery import PublicReceipt
from .evidence import EvidenceContext, EvidenceEnvelope, WrappedKey
from .ledger import AuthRecord, QuorumPolicy, TxState
from .pam import PAMOpening, ProofKind
from .rbc import QuorumRBC, RBCBody, VerificationAttestation
from .registry import KeyRecord, KeyRegistry, KeyStatus, Role, _Entity
from .verifier import SettlementRequest, VerifierOutcome

_CLASSES = {c.__name__: c for c in (PublicReceipt, EvidenceContext, EvidenceEnvelope,
    WrappedKey, AuthRecord, QuorumPolicy, PAMOpening, RBCBody, VerificationAttestation,
    QuorumRBC, SettlementRequest, VerifierOutcome, KeyRecord, _Entity)}
_ENUMS = {c.__name__: c for c in (TxState, ProofKind, KeyStatus, Role)}


def _pack(x: Any) -> Any:
    if isinstance(x, Enum):
        return {"@enum": type(x).__name__, "value": x.value}
    if isinstance(x, Decimal):
        return {"@decimal": str(x)}
    if isinstance(x, bytes):
        return {"@bytes": x.hex()}
    if isinstance(x, tuple):
        return {"@tuple": [_pack(v) for v in x]}
    if isinstance(x, set):
        return {"@set": [_pack(v) for v in sorted(x, key=repr)]}
    if dataclasses.is_dataclass(x):
        name = type(x).__name__
        if name not in _CLASSES:
            raise TypeError(f"unlisted wire record: {name}")
        return {"@record": name, "fields": {f.name: _pack(getattr(x, f.name))
                                             for f in dataclasses.fields(x)}}
    if isinstance(x, dict):
        if not all(isinstance(k, str) and not k.startswith("@") for k in x):
            raise TypeError("wire dictionaries need non-reserved string keys")
        return {k: _pack(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_pack(v) for v in x]
    if x is None or isinstance(x, (str, int, float, bool)):
        return x
    raise TypeError(type(x).__name__)


def _unpack(x: Any) -> Any:
    if isinstance(x, list):
        return [_unpack(v) for v in x]
    if not isinstance(x, dict):
        return x
    if "@enum" in x:
        return _ENUMS[x["@enum"]](x["value"])
    if "@decimal" in x:
        return Decimal(x["@decimal"])
    if "@bytes" in x:
        return bytes.fromhex(x["@bytes"])
    if "@tuple" in x:
        return tuple(_unpack(v) for v in x["@tuple"])
    if "@set" in x:
        return set(_unpack(v) for v in x["@set"])
    if "@record" in x:
        cls = _CLASSES[x["@record"]]
        return cls(**{k: _unpack(v) for k, v in x["fields"].items()})
    if any(k.startswith("@") for k in x):
        raise ValueError("unknown wire tag")
    return {k: _unpack(v) for k, v in x.items()}


def dumps(x: Any) -> bytes:
    return json.dumps(_pack(x), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def loads(data: bytes) -> Any:
    return _unpack(json.loads(data))


def registry_dump(reg: KeyRegistry) -> bytes:
    return dumps({"entities": reg._entities, "meter_station": reg.meter_station,
        "station_operator": reg.station_operator, "station_beneficiary": reg.station_beneficiary,
        "user_home": reg.user_home, "tariffs": reg.tariffs, "verifier_set_epoch": reg.verifier_set_epoch})


def registry_load(data: bytes) -> KeyRegistry:
    d = loads(data)
    reg = KeyRegistry()
    reg._entities = d["entities"]
    for k in ("meter_station", "station_operator", "station_beneficiary", "user_home", "tariffs",
              "verifier_set_epoch"):
        setattr(reg, k, d[k])
    return reg
