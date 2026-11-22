"""
Key/role registry with activation, revocation, rotation and key epochs.

Registry assumptions (explicit and testable, not cryptographically enforced):
- the registration authority (RA) correctly binds entity IDs, roles,
  operators and public keys (a malicious RA is out of scope)
- registry state is read consistently by verifiers and SettleSC
  (contract-state simulation, on chain this is contract storage)
- revocation takes effect for every lookup after it is recorded.

Each record carries: entity_id, role, operator, public key, key type,
purpose (sig/kem), key epoch, status and an optional validity interval.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Iterable

from .instrumentation import count


class Role(str, Enum):
    USER = "USER"
    STATION = "STATION"
    METER = "METER"
    VERIFIER = "VERIFIER"


class KeyStatus(str, Enum):
    REGISTERED = "REGISTERED"
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    REVOKED = "REVOKED"


@dataclass(frozen=True)
class KeyRecord:
    entity_id: str
    role: Role
    operator: str
    public_key: bytes
    key_type: str
    purpose: str
    key_epoch: int
    status: KeyStatus
    valid_from: int = 0
    valid_until: int | None = None


@dataclass(frozen=True)
class Lookup:
    ok: bool
    reason: str
    record: KeyRecord | None = None


@dataclass
class _Entity:
    entity_id: str
    role: Role
    operator: str
    revoked: bool = False
    keys: dict[str, list[KeyRecord]] = field(default_factory=dict)  # purpose -> history


class KeyRegistry:
    def __init__(self) -> None:
        self._entities: dict[str, _Entity] = {}
        self.meter_station: dict[str, str] = {}
        self.station_operator: dict[str, str] = {}
        self.station_beneficiary: dict[str, str] = {}
        self.user_home: dict[str, str] = {}
        self.tariffs: set[tuple[Any, ...]] = set()
        self.verifier_set_epoch = 0

    # -- lifecycle ----------------------------------------------------------
    def register(
        self,
        entity_id: str,
        role: Role,
        operator: str,
        public_key: bytes,
        key_type: str,
        *,
        purpose: str = "sig",
        activate: bool = True,
        valid_from: int = 0,
        valid_until: int | None = None,
    ) -> KeyRecord:
        ent = self._entities.get(entity_id)
        if ent is None:
            ent = _Entity(entity_id, role, operator)
            self._entities[entity_id] = ent
        elif ent.role != role:
            raise ValueError(f"{entity_id} already registered with role {ent.role.value}")
        if ent.revoked:
            raise ValueError(f"{entity_id} is revoked")
        hist = ent.keys.setdefault(purpose, [])
        if any(r.status == KeyStatus.ACTIVE for r in hist):
            raise ValueError(f"{entity_id} already has an active {purpose} key; use rotate()")
        rec = KeyRecord(entity_id, role, operator, bytes(public_key), key_type, purpose, len(hist) + 1,
                        KeyStatus.ACTIVE if activate else KeyStatus.REGISTERED, valid_from, valid_until)
        hist.append(rec)
        if role == Role.USER:
            self.user_home[entity_id] = operator
        if role == Role.STATION:
            self.station_operator[entity_id] = operator
        if role == Role.VERIFIER:
            self.verifier_set_epoch += 1
        return rec

    def activate(self, entity_id: str, purpose: str = "sig") -> KeyRecord:
        ent = self._entities[entity_id]
        hist = ent.keys[purpose]
        if ent.revoked:
            raise ValueError("cannot activate a revoked entity")
        last = hist[-1]
        if last.status != KeyStatus.REGISTERED:
            raise ValueError(f"latest key is {last.status.value}")
        hist[-1] = replace(last, status=KeyStatus.ACTIVE)
        if ent.role == Role.VERIFIER:
            self.verifier_set_epoch += 1
        return hist[-1]

    def rotate(self, entity_id: str, new_public_key: bytes, key_type: str, purpose: str = "sig") -> KeyRecord:
        ent = self._entities[entity_id]
        if ent.revoked:
            raise ValueError("cannot rotate a revoked entity")
        hist = ent.keys[purpose]
        for i, r in enumerate(hist):
            if r.status in (KeyStatus.ACTIVE, KeyStatus.REGISTERED):
                hist[i] = replace(r, status=KeyStatus.SUPERSEDED)
        rec = KeyRecord(entity_id, ent.role, ent.operator, bytes(new_public_key), key_type, purpose,
                        len(hist) + 1, KeyStatus.ACTIVE)
        hist.append(rec)
        if ent.role == Role.VERIFIER:
            self.verifier_set_epoch += 1
        return rec

    def revoke(self, entity_id: str) -> None:
        ent = self._entities[entity_id]
        ent.revoked = True
        for purpose, hist in ent.keys.items():
            ent.keys[purpose] = [replace(r, status=KeyStatus.REVOKED) if r.status != KeyStatus.SUPERSEDED else r
                                 for r in hist]
        if ent.role == Role.VERIFIER:
            self.verifier_set_epoch += 1

    # -- lookups ------------------------------------------------------------
    def role_of(self, entity_id: str) -> Role | None:
        ent = self._entities.get(entity_id)
        return ent.role if ent else None

    def operator_of(self, entity_id: str) -> str | None:
        ent = self._entities.get(entity_id)
        return ent.operator if ent else None

    def lookup(self, entity_id: str, role: Role, *, purpose: str = "sig", epoch: int | None = None,
               at: int | None = None) -> Lookup:
        """Resolve the active key of ``entity_id`` in ``role``.

        epoch=None returns the active key. An explicit epoch must equal the
        active epoch (older epochs are STALE_EPOCH).
        """
        count("registry_lookup")
        ent = self._entities.get(entity_id)
        if ent is None:
            return Lookup(False, "UNREGISTERED")
        if ent.role != role:
            return Lookup(False, "WRONG_ROLE")
        if ent.revoked:
            return Lookup(False, "REVOKED")
        hist = ent.keys.get(purpose)
        if not hist:
            return Lookup(False, "NO_KEY")
        active = [r for r in hist if r.status == KeyStatus.ACTIVE]
        if not active:
            return Lookup(False, "NOT_ACTIVE")
        rec = active[-1]
        if epoch is not None and epoch != rec.key_epoch:
            if 0 < epoch < rec.key_epoch:
                return Lookup(False, "STALE_EPOCH")
            return Lookup(False, "UNKNOWN_EPOCH")
        if at is not None and (at < rec.valid_from or (rec.valid_until is not None and at > rec.valid_until)):
            return Lookup(False, "EXPIRED")
        return Lookup(True, "OK", rec)

    def active_verifiers(self) -> list[KeyRecord]:
        out = []
        for ent in self._entities.values():
            if ent.role == Role.VERIFIER and not ent.revoked:
                lk = self.lookup(ent.entity_id, Role.VERIFIER, purpose="sig")
                if lk.ok:
                    out.append(lk.record)  # type: ignore[arg-type]
        return sorted(out, key=lambda r: r.entity_id)

    def active_verifier_kem_keys(self) -> list[KeyRecord]:
        out = []
        for rec in self.active_verifiers():
            lk = self.lookup(rec.entity_id, Role.VERIFIER, purpose="kem")
            if lk.ok:
                out.append(lk.record)  # type: ignore[arg-type]
        return out

    # -- semantic bindings (RA-maintained) ---------------------------------
    def bind_meter(self, meter_id: str, station_id: str) -> None:
        if self.role_of(meter_id) != Role.METER or self.role_of(station_id) != Role.STATION:
            raise ValueError("bind_meter requires a registered METER and STATION")
        self.meter_station[meter_id] = station_id

    def set_beneficiary(self, station_id: str, beneficiary: str) -> None:
        self.station_beneficiary[station_id] = beneficiary

    def publish_tariff(self, station_id: str, tariff_id: str, tariff_version: str, mode: str,
                       unit_price: Any, currency: str) -> None:
        """Publish a tariff entry. The catalog is functional in (station, tariff_id, version).

        Re-publishing the identical tuple is idempotent. A different
        (mode, unit_price, currency) for an existing key is rejected, which
        enforces assumption A2 of the minimality proof.
        """
        entry = (station_id, tariff_id, tariff_version, mode, unit_price, currency)
        for existing in self.tariffs:
            if existing[:3] == entry[:3] and existing != entry:
                raise ValueError(
                    f"tariff ({station_id}, {tariff_id}, {tariff_version}) already published "
                    "with different terms"
                )
        self.tariffs.add(entry)

    def relations(self) -> dict[str, Any]:
        """Relation callbacks used by predicate evaluation."""

        def meter_bound(meter_id: str, station_id: str) -> bool:
            if self.role_of(meter_id) != Role.METER or not self.lookup(meter_id, Role.METER).ok:
                return False
            return self.meter_station.get(meter_id) == station_id

        def station_operated_by(station_id: str, operator: str) -> bool:
            return self.station_operator.get(station_id) == operator and self.lookup(station_id, Role.STATION).ok

        return {
            "meter_bound_to_station": meter_bound,
            "station_operated_by": station_operated_by,
            "user_home_operator": lambda u, op: self.user_home.get(u) == op and self.lookup(u, Role.USER).ok,
            "station_beneficiary": lambda s, b: self.station_beneficiary.get(s) == b,
            "tariff_published": lambda *t: tuple(t) in self.tariffs,
        }

    def entities(self, role: Role | None = None) -> Iterable[str]:
        return [e.entity_id for e in self._entities.values() if role is None or e.role == role]
