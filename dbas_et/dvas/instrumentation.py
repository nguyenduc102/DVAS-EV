"""
Lightweight operation counters for controlled-baseline accounting.

Counts are collected per context (``OpCounter`` used as a context manager),
outside a context the calls are no-ops.  Counted categories:

hash, sig_gen, sig_verify, kem_encap, kem_decap, aead_enc, aead_dec,
proof_gen, proof_verify, state_transition, bound_check, retained_object,
public_bytes, private_bytes.
"""

from __future__ import annotations

import contextvars
from collections import Counter
from typing import Any

_current: contextvars.ContextVar["OpCounter | None"] = contextvars.ContextVar("dvas_opcounter", default=None)


class OpCounter:
    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self._token: Any = None

    def __enter__(self) -> "OpCounter":
        self._token = _current.set(self)
        return self

    def __exit__(self, *exc: Any) -> None:
        _current.reset(self._token)

    def as_dict(self, prefix: str = "") -> dict[str, int]:
        return {f"{prefix}{k}": int(v) for k, v in sorted(self.counts.items())}


def count(kind: str, n: int = 1) -> None:
    c = _current.get()
    if c is not None:
        c.counts[kind] += n
