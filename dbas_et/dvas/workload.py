"""
Workload adapters: ACN / MFEV processed profiles -> DVAS-EV session specs.

Provenance rules
----------------
* Energy, timestamps and durations are copied from the processed dataset
  rows (ACN-Data sessions, MFEV SciData 2024 charging records).  Nothing
  physical is synthesised.
* Tariff, pre-authorisation limits and top-up deltas are the legacy
  artifact's deterministic protocol tariff (``tariff_source`` column), not
  real billing data.
* MFEV has no active/parking split.  Durations are derived only from the
  dataset's own connection / doneCharging / disconnect timestamps.
* The multi-operator scenario (``assign_operators``) relabels home
  operators with a deterministic hash of the user ID.  This is a scenario
  mapping, and the output labels it so (``operator_assignment``).
"""

from __future__ import annotations

import csv
import hashlib
from dataclasses import dataclass, field, replace
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterator
from zoneinfo import ZoneInfo

from ..capsule import build_trade_id
from .canonical import to_fixed6

ROOT = Path(__file__).resolve().parents[2]
ACN_VALID = ROOT / "data" / "acn" / "processed" / "profile_valid_preauthorization.csv"
ACN_ORIGINAL_CAP = ROOT / "data" / "acn" / "processed" / "profile_original_cap.csv"
ACN_TOPUP = ROOT / "data" / "acn" / "processed" / "profile_undercap_topup.csv"
MFEV_VALID_5K = ROOT / "data" / "processed" / "mfev" / "runner_fixed" / "mfev_5000_valid_fixed.csv"


@dataclass(frozen=True)
class SessionSpec:
    source: str
    row_index: int
    session_ref: str
    tid: str
    user_id: str
    home_operator: str
    station_id: str
    foreign_operator: str
    meter_id: str
    beneficiary: str
    evse_id: str | None
    tariff_id: str
    tariff_version: str
    tariff_mode: str
    unit_price: Decimal
    currency: str
    requested_kwh: Decimal
    cap_kwh: Decimal
    preauth_limit: Decimal
    tw_start: int
    tw_end: int
    nonce_u: str
    nonce_s: str
    created_at: int
    delivered_kwh: Decimal
    ts_start: int
    ts_end: int
    connection_duration_s: int
    active_charging_duration_s: int
    parking_duration_s: int
    expected_amount: Decimal
    topup_delta: Decimal = Decimal(0)
    expected_undercap: bool = False
    operator_assignment: str = "dataset"
    extra: dict[str, Any] = field(default_factory=dict)


def _b(v: Any) -> bool:
    return str(v).strip().lower() in {"true", "1", "yes", "t"}


def _int(v: Any, default: int = 0) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _read(path: Path, max_rows: int | None) -> Iterator[tuple[int, dict[str, str]]]:
    with open(path, newline="", encoding="utf-8") as f:
        for i, row in enumerate(csv.DictReader(f)):
            if max_rows is not None and i >= max_rows:
                return
            yield i, row


def acn_sessions(path: Path = ACN_VALID, max_rows: int | None = None, *, preauth_column: str = "preauth_limit_t") -> list[SessionSpec]:
    out = []
    for i, r in _read(path, max_rows):
        nonce_u = f"acn-user-{i}-{r.get('source_session_id', '')}"
        nonce_s = f"acn-station-{i}-{r.get('source_station_id', '')}"
        user, station, meter = r["protocol_user_id"], r["protocol_station_id"], r["protocol_meter_id"]
        tid = build_trade_id(user_id=user, station_id=station, meter_id=meter, nonce_u=nonce_u, nonce_s=nonce_s)
        tw_s, tw_e = _int(r["tw_start"]), _int(r["tw_end"])
        out.append(SessionSpec(
            source="ACN-Data", row_index=i, session_ref=r.get("source_session_id", ""), tid=tid,
            user_id=user, home_operator=r.get("home_domain", "OH_ACN"), station_id=station,
            foreign_operator=r.get("foreign_domain", "OF_ACN"), meter_id=meter, beneficiary=f"BEN_{station}",
            evse_id=r.get("source_station_id") or None, tariff_id=r["tariff_id"], tariff_version=r["tariff_version"],
            tariff_mode=r["tariff_mode"], unit_price=to_fixed6(r["unit_price"]), currency="TOKEN",
            requested_kwh=to_fixed6(r["requested_kwh"]), cap_kwh=to_fixed6(r["cap_kwh"]),
            preauth_limit=to_fixed6(r[preauth_column]), tw_start=tw_s, tw_end=tw_e, nonce_u=nonce_u,
            nonce_s=nonce_s, created_at=tw_s, delivered_kwh=to_fixed6(r["delivered_kwh"]), ts_start=tw_s,
            ts_end=tw_e, connection_duration_s=_int(r.get("connection_duration_s")),
            active_charging_duration_s=_int(r.get("active_charging_duration_s")),
            parking_duration_s=_int(r.get("parking_duration_s")),
            expected_amount=to_fixed6(r["expected_amount"]),
            topup_delta=to_fixed6(r.get("topup_delta_recommended") or 0),
            expected_undercap=_b(r.get("is_undercap_original", False)),
        ))
    return out


def _ts(s: str, tz: ZoneInfo) -> int:
    return int(datetime.strptime(s.strip()[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz).timestamp())


def mfev_sessions(path: Path = MFEV_VALID_5K, max_rows: int | None = None) -> list[SessionSpec]:
    out = []
    for i, r in _read(path, max_rows):
        tz = ZoneInfo(r.get("timezone") or "Asia/Seoul")
        start, end = _ts(r["connectionTime"], tz), _ts(r["disconnectTime"], tz)
        done = _ts(r["doneChargingTime"], tz) if r.get("doneChargingTime") else end
        done = min(max(done, start), end)
        conn = end - start
        active, parking = done - start, end - done
        station = r["station_id"]
        out.append(SessionSpec(
            source="MFEV", row_index=i, session_ref=r.get("source_session_id", ""), tid=r["trade_id"],
            user_id=r["user_id"], home_operator=r["home_domain"], station_id=station,
            foreign_operator=r["foreign_domain"], meter_id=r["meter_id"], beneficiary=f"BEN_{station}",
            evse_id=r.get("evse_id") or None, tariff_id=r["tariff_id"], tariff_version=r["tariff_version"],
            tariff_mode=r["tariff_mode"], unit_price=to_fixed6(r["unit_price"]), currency=r.get("currency") or "TOKEN",
            requested_kwh=to_fixed6(r["requested_kwh"]), cap_kwh=to_fixed6(r["cap_kwh"]),
            preauth_limit=to_fixed6(r["preauth_limit_t"]), tw_start=_ts(r["tw_start"], tz), tw_end=_ts(r["tw_end"], tz),
            nonce_u=r["nonce_u"], nonce_s=r["nonce_s"], created_at=start, delivered_kwh=to_fixed6(r["delivered_kwh"]),
            ts_start=start, ts_end=end, connection_duration_s=conn, active_charging_duration_s=active,
            parking_duration_s=parking, expected_amount=to_fixed6(r["expected_amount"]),
            expected_undercap=_b(r.get("is_undercap_case", False)),
        ))
    return out


OPERATORS = ("OP_A", "OP_B", "OP_C")


def _bucket(s: str) -> int:
    return int(hashlib.sha256(s.encode()).hexdigest(), 16) % len(OPERATORS)


def assign_operators(specs: list[SessionSpec], cpo_map: dict[str, str]) -> list[SessionSpec]:
    """Multi-operator scenario: users -> home operator by hash(user_id), and
    stations keep their dataset CPO, relabelled through ``cpo_map``."""
    out = []
    for s in specs:
        home = OPERATORS[_bucket(s.user_id)]
        cpo = cpo_map.get(s.foreign_operator, s.foreign_operator)
        out.append(replace(s, home_operator=home, foreign_operator=cpo,
                           operator_assignment="scenario:home=hash(user_id)%3;cpo=dataset_operator_relabelled"))
    return out


def honest_amount(spec: SessionSpec) -> Decimal:
    """Exact (Decimal, ROUND_HALF_EVEN) tariff amount of a session: the honest reference
    used by experiment harnesses.  The dataset's precomputed ``expected_amount``
    column was produced with float rounding and differs by 1e-6 on 4 of 5,000 ACN
    rows (exact half-way cases). Harnesses therefore compare against this value."""
    from .tariff import tariff_amount

    return tariff_amount(mode=spec.tariff_mode, unit_price=spec.unit_price, delivered_kwh=spec.delivered_kwh,
                         connection_duration_s=spec.connection_duration_s,
                         active_charging_duration_s=spec.active_charging_duration_s,
                         parking_duration_s=spec.parking_duration_s)
