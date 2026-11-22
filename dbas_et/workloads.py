"""
Real ACN workload loading, normalization, and DBAS-ET profile generation.

This module downloads or loads real ACN-Data charging sessions and converts
them into protocol-level workload rows for DBAS-ET.

Notes
-----
1. ACN session rows are real EV charging sessions.
2. The tariff fields generated here are deterministic protocol tariff fields.
   They are not ACN billing tariffs.
3. preauth_limit_t means pre-authorized payment limit, not captured payment.
4. Raw API tokens are never stored in outputs.
5. Raw downloaded sessions may exceed target_n. The processed DBAS-ET workload
   is then selected to exactly target_n usable normalized sessions.
"""

from __future__ import annotations

import json
import math
import os
import re
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

from .crypto import H_hex
from .payments import eval_tariff_amount


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data" / "acn"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"

DEFAULT_ACN_BASE_URL = "https://ev.caltech.edu/api/v1/"
DEFAULT_SITES = ("caltech", "jpl", "office001")


@dataclass(frozen=True)
class ACNDownloadConfig:
    """
    Configuration for downloading ACN sessions.

    target_raw_sessions:
        Number of raw sessions to cache before normalization. This should be
        larger than target_n because some rows may be unusable after filtering.
    """

    api_token: str
    target_raw_sessions: int
    sites: tuple[str, ...] = DEFAULT_SITES
    base_url: str = DEFAULT_ACN_BASE_URL
    min_energy_kwh: float = 0.1
    timeout_s: int = 60
    sleep_s: float = 0.10
    sort: str = "-connectionTime"

    def safe_record(self) -> dict[str, Any]:
        """Return metadata without exposing API token."""
        return {
            "target_raw_sessions": int(self.target_raw_sessions),
            "sites": ",".join(self.sites),
            "base_url": self.base_url,
            "min_energy_kwh": float(self.min_energy_kwh),
            "timeout_s": int(self.timeout_s),
            "sleep_s": float(self.sleep_s),
            "sort": self.sort,
            "api_token_present": bool(self.api_token),
        }


def ensure_acn_dirs() -> tuple[Path, Path]:
    """Create ACN data folders."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    return RAW_DIR, PROCESSED_DIR


def sanitize_token_for_filename(value: str) -> str:
    """Return a filesystem-safe identifier."""
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip())
    cleaned = cleaned.strip("-").lower()
    return cleaned or "unknown"


def sites_slug(sites: Iterable[str]) -> str:
    """Build stable slug for site list."""
    return "-".join(sanitize_token_for_filename(s) for s in sites)


def min_kwh_slug(min_kwh: float) -> str:
    """Build stable slug for minimum energy threshold."""
    return str(float(min_kwh)).replace(".", "p")


def raw_cache_path(
    sites: Iterable[str],
    min_energy_kwh: float,
    raw_limit: int,
) -> Path:
    """Return raw cache path that includes filtering parameters."""
    return RAW_DIR / (
        f"acn_sessions_sites-{sites_slug(sites)}"
        f"_min{min_kwh_slug(min_energy_kwh)}"
        f"_raw{int(raw_limit)}.jsonl"
    )


def workload_cache_prefix(
    target_n: int,
    sites: Iterable[str],
    min_energy_kwh: float,
) -> str:
    """Return stable prefix for processed workload files."""
    return (
        f"sites-{sites_slug(sites)}"
        f"_min{min_kwh_slug(min_energy_kwh)}"
        f"_n{int(target_n)}"
    )


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        if isinstance(value, str) and value.strip() == "":
            return default
        out = float(value)
        if math.isnan(out) or math.isinf(out):
            return default
        return out
    except Exception:
        return default


def _parse_dt(value: Any) -> pd.Timestamp | None:
    """Parse timestamp to UTC pandas Timestamp."""
    if value is None or value == "":
        return None
    try:
        ts = pd.to_datetime(value, utc=True, errors="coerce")
        if pd.isna(ts):
            return None
        return ts
    except Exception:
        return None


def _to_unix_seconds(ts: pd.Timestamp | None) -> int:
    if ts is None:
        return 0
    return int(ts.timestamp())


def _duration_seconds(start: pd.Timestamp | None, end: pd.Timestamp | None) -> int:
    if start is None or end is None:
        return 0
    seconds = int((end - start).total_seconds())
    return max(0, seconds)


def _get_first(raw: dict[str, Any], keys: Iterable[str], default: Any = None) -> Any:
    for key in keys:
        if key in raw and raw[key] is not None:
            return raw[key]
    return default


def _extract_requested_kwh(raw: dict[str, Any], delivered_kwh: float) -> tuple[float, bool, str]:
    """
    Extract requested energy if available.

    If no explicit requested energy exists, delivered_kwh is used as a
    conservative protocol request and marked as imputed.
    """
    direct_keys = [
        "kWhRequested",
        "requested_kWh",
        "requested_kwh",
        "energyRequested",
        "energy_requested",
    ]

    for key in direct_keys:
        if key in raw:
            v = _safe_float(raw.get(key), default=0.0)
            if v > 0:
                return v, True, key

    user_inputs = raw.get("userInputs")
    candidates: list[dict[str, Any]] = []

    if isinstance(user_inputs, list):
        candidates = [x for x in user_inputs if isinstance(x, dict)]
    elif isinstance(user_inputs, dict):
        candidates = [user_inputs]

    for item in candidates:
        for key in direct_keys:
            if key in item:
                v = _safe_float(item.get(key), default=0.0)
                if v > 0:
                    return v, True, f"userInputs.{key}"

        miles = _safe_float(item.get("milesRequested"), default=0.0)
        wh_per_mile = _safe_float(item.get("WhPerMile"), default=0.0)
        if miles > 0 and wh_per_mile > 0:
            return miles * wh_per_mile / 1000.0, True, "userInputs.milesRequested*WhPerMile"

    return max(float(delivered_kwh), 0.1), False, "imputed_from_delivered_kwh"


def _stable_protocol_user_id(site_id: str, raw_user_id: Any) -> str:
    if raw_user_id is None or str(raw_user_id).strip() == "":
        raw_user_id = "anonymous"
    return "U_" + H_hex("H_ACN_USER_ID", {"site": site_id, "user": str(raw_user_id)})[:10]


def _stable_station_id(site_id: str, raw_station_id: Any) -> str:
    if raw_station_id is None or str(raw_station_id).strip() == "":
        raw_station_id = "unknown_station"
    return "S_" + H_hex("H_ACN_STATION_ID", {"site": site_id, "station": str(raw_station_id)})[:10]


def _stable_meter_id(site_id: str, station_id: str) -> str:
    return "M_" + H_hex("H_ACN_METER_ID", {"site": site_id, "station_id": station_id})[:10]


def _site_domain(site_id: str) -> str:
    return "OF_" + site_id.upper().replace("-", "_")


def _deterministic_tariff_fields(
    site_id: str,
    session_id: str,
    connection_time: pd.Timestamp | None,
) -> dict[str, Any]:
    """
    Deterministic protocol tariff model.

    This is not ACN billing. It creates reproducible tariff fields for
    DBAS-ET protocol evaluation.
    """
    hour = int(connection_time.hour) if connection_time is not None else 12
    is_peak = 8 <= hour < 18

    site = site_id.lower()
    if site == "caltech":
        base_peak = 0.55
        base_offpeak = 0.32
    elif site == "jpl":
        base_peak = 0.52
        base_offpeak = 0.30
    else:
        base_peak = 0.50
        base_offpeak = 0.28

    selector = int(H_hex("H_TARIFF_MODE_SELECT", {"site": site_id, "session": session_id})[:8], 16) % 10

    if selector < 5:
        mode = "ENERGY_ONLY"
    elif selector < 8:
        mode = "ENERGY_ACTIVE_TIME"
    else:
        mode = "ENERGY_ACTIVE_PARKING"

    price_class = "PEAK" if is_peak else "OFFPEAK"
    unit_price = base_peak if is_peak else base_offpeak

    return {
        "tariff_id": f"{site_id.upper()}_{price_class}_{mode}",
        "tariff_version": "acn-derived-v1",
        "tariff_mode": mode,
        "unit_price": round(float(unit_price), 6),
        "tariff_source": "deterministic_protocol_tariff_not_acn_billing",
    }


def _extract_items(response_json: Any) -> list[dict[str, Any]]:
    if isinstance(response_json, list):
        return [x for x in response_json if isinstance(x, dict)]

    if isinstance(response_json, dict):
        for key in ("_items", "items", "sessions", "data"):
            value = response_json.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]

    return []


def _extract_next_href(response_json: Any) -> str | None:
    if not isinstance(response_json, dict):
        return None

    links = response_json.get("_links")
    if not isinstance(links, dict):
        return None

    next_obj = links.get("next")
    if not isinstance(next_obj, dict):
        return None

    href = next_obj.get("href")
    return str(href) if href else None


def _join_api_url(base_url: str, href: str) -> str:
    if href.startswith("http://") or href.startswith("https://"):
        return href
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", href)


def _build_where_clause(min_energy_kwh: float) -> str:
    return f"kWhDelivered>={float(min_energy_kwh)}"


def fetch_acn_sessions_rest(config: ACNDownloadConfig) -> list[dict[str, Any]]:
    """
    Fetch real ACN sessions using the official REST API.

    Authentication:
        token as HTTP basic-auth username, blank password.

    Resilient version for large downloads:
      - retries transient HTTP 429/500/502/503/504;
      - uses exponential backoff;
      - prints progress;
      - can move to the next site if one site repeatedly fails after partial data;
      - fails immediately for 401/403 because token/auth will not be fixed by retry.
    """
    try:
        import requests
    except Exception as exc:
        raise RuntimeError(
            "requests is required to download ACN data. Install with: pip install requests"
        ) from exc

    if not config.api_token:
        raise ValueError("api_token is required for ACN REST download")

    sessions: list[dict[str, Any]] = []
    where_clause = _build_where_clause(config.min_energy_kwh)

    transient_statuses = {429, 500, 502, 503, 504}

    # Tunable through env vars without changing the dataclass.
    max_retries_per_page = int(os.environ.get("ACN_MAX_RETRIES_PER_PAGE", "8"))
    base_backoff_s = float(os.environ.get("ACN_BASE_BACKOFF_S", "2.0"))
    max_backoff_s = float(os.environ.get("ACN_MAX_BACKOFF_S", "60.0"))
    progress_pages = int(os.environ.get("ACN_PROGRESS_PAGES", "50"))
    allow_site_skip_after_retries = os.environ.get("ACN_ALLOW_SITE_SKIP", "1") != "0"

    for site_id in config.sites:
        if len(sessions) >= config.target_raw_sessions:
            break

        endpoint = urllib.parse.urljoin(
            config.base_url.rstrip("/") + "/",
            f"sessions/{site_id}",
        )

        params = {
            "where": where_clause,
            "sort": config.sort,
        }

        next_url: str | None = endpoint
        next_params: dict[str, Any] | None = params
        page_no = 0
        site_sessions_before = len(sessions)

        print(
            f"[acn] start site={site_id}, already_collected={len(sessions)}, "
            f"target_raw={config.target_raw_sessions}",
            flush=True,
        )

        while next_url and len(sessions) < config.target_raw_sessions:
            page_no += 1
            last_error: str | None = None
            resp = None

            for attempt in range(1, max_retries_per_page + 1):
                try:
                    resp = requests.get(
                        next_url,
                        params=next_params,
                        auth=(config.api_token, ""),
                        timeout=config.timeout_s,
                    )
                except requests.exceptions.RequestException as exc:
                    last_error = f"request_exception={type(exc).__name__}: {exc}"
                    sleep_s = min(max_backoff_s, base_backoff_s * (2 ** (attempt - 1)))
                    print(
                        f"[acn] retry site={site_id} page={page_no} "
                        f"attempt={attempt}/{max_retries_per_page} after {last_error}; "
                        f"sleep={sleep_s:.1f}s",
                        flush=True,
                    )
                    time.sleep(sleep_s)
                    continue

                if resp.status_code == 200:
                    last_error = None
                    break

                if resp.status_code in {401, 403}:
                    raise RuntimeError(
                        f"ACN API authentication/authorization failed: site={site_id}, "
                        f"status={resp.status_code}, body={resp.text[:300]}"
                    )

                if resp.status_code in transient_statuses:
                    last_error = f"status={resp.status_code}, body={resp.text[:180]}"
                    sleep_s = min(max_backoff_s, base_backoff_s * (2 ** (attempt - 1)))
                    print(
                        f"[acn] retry site={site_id} page={page_no} "
                        f"attempt={attempt}/{max_retries_per_page} after {last_error}; "
                        f"sleep={sleep_s:.1f}s",
                        flush=True,
                    )
                    time.sleep(sleep_s)
                    continue

                raise RuntimeError(
                    f"ACN API request failed: site={site_id}, status={resp.status_code}, "
                    f"body={resp.text[:300]}"
                )

            if resp is None or resp.status_code != 200:
                msg = (
                    f"ACN API page failed after retries: site={site_id}, page={page_no}, "
                    f"collected_total={len(sessions)}, "
                    f"collected_site={len(sessions)-site_sessions_before}, "
                    f"last_error={last_error}"
                )

                if allow_site_skip_after_retries and len(sessions) > site_sessions_before:
                    print(f"[acn] warning: {msg}; moving to next site", flush=True)
                    break

                raise RuntimeError(msg)

            payload = resp.json()
            items = _extract_items(payload)

            for item in items:
                if len(sessions) >= config.target_raw_sessions:
                    break
                item = dict(item)
                item["_acn_site_id"] = site_id
                item["_downloaded_at_utc"] = _now_utc_iso()
                sessions.append(item)

            if progress_pages > 0 and (page_no == 1 or page_no % progress_pages == 0):
                print(
                    f"[acn] site={site_id} page={page_no} items={len(items)} "
                    f"collected={len(sessions)}/{config.target_raw_sessions}",
                    flush=True,
                )

            href = _extract_next_href(payload)
            next_url = _join_api_url(config.base_url, href) if href else None
            next_params = None

            if config.sleep_s > 0:
                time.sleep(config.sleep_s)

            if not items and not href:
                print(
                    f"[acn] site={site_id} has no more items; "
                    f"collected_site={len(sessions)-site_sessions_before}",
                    flush=True,
                )
                break

        print(
            f"[acn] done site={site_id}, "
            f"collected_site={len(sessions)-site_sessions_before}, "
            f"collected_total={len(sessions)}/{config.target_raw_sessions}",
            flush=True,
        )

    if not sessions:
        raise RuntimeError(
            "ACN download returned zero sessions. Check token, network, site names, and API availability."
        )

    if len(sessions) < config.target_raw_sessions:
        print(
            f"[acn] warning: collected only {len(sessions)}/{config.target_raw_sessions} raw sessions. "
            "The caller may retry with lower min-kWh, more sites, or a larger download attempt.",
            flush=True,
        )

    return sessions

def save_raw_sessions_jsonl(sessions: list[dict[str, Any]], path: Path) -> None:
    """Save raw ACN sessions as JSONL."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in sessions:
            f.write(json.dumps(row, sort_keys=True, default=str) + "\n")


def load_raw_sessions_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load raw ACN sessions from JSONL."""
    if not path.exists():
        raise FileNotFoundError(f"raw ACN file not found: {path}")

    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def normalize_acn_sessions(raw_sessions: list[dict[str, Any]]) -> pd.DataFrame:
    """
    Normalize real ACN sessions into stable protocol-friendly rows.

    Rows with missing timestamps or non-positive energy are dropped.
    """
    records: list[dict[str, Any]] = []

    for idx, raw in enumerate(raw_sessions):
        site_id = str(raw.get("_acn_site_id") or raw.get("siteID") or raw.get("site") or "unknown")

        session_id_raw = (
            raw.get("_id")
            or raw.get("sessionID")
            or raw.get("sessionId")
            or raw.get("id")
            or f"{site_id}_row_{idx}"
        )
        session_id = str(session_id_raw)

        connection_time = _parse_dt(_get_first(raw, ["connectionTime", "connection_time"]))
        disconnect_time = _parse_dt(_get_first(raw, ["disconnectTime", "disconnect_time"]))
        done_charging_time = _parse_dt(
            _get_first(raw, ["doneChargingTime", "done_charging_time", "doneCharging"])
        )

        delivered_kwh = _safe_float(
            _get_first(raw, ["kWhDelivered", "kwhDelivered", "energyDelivered", "energy_kwh"]),
            default=0.0,
        )

        if connection_time is None or disconnect_time is None:
            continue
        if delivered_kwh <= 0:
            continue

        connection_duration_s = _duration_seconds(connection_time, disconnect_time)

        if connection_duration_s <= 0:
            continue

        if done_charging_time is not None:
            active_charging_duration_s = min(
                connection_duration_s,
                _duration_seconds(connection_time, done_charging_time),
            )
        else:
            estimated_active_s = int((delivered_kwh / 6.6) * 3600)
            active_charging_duration_s = min(connection_duration_s, max(0, estimated_active_s))

        parking_duration_s = max(0, connection_duration_s - active_charging_duration_s)

        raw_station_id = _get_first(
            raw,
            ["stationID", "stationId", "EVSEID", "evseID", "spaceID", "spaceId"],
            default="unknown_station",
        )
        station_id = _stable_station_id(site_id, raw_station_id)
        meter_id = _stable_meter_id(site_id, station_id)

        raw_user_id = _get_first(raw, ["userID", "userId", "user_id"], default="anonymous")
        user_id = _stable_protocol_user_id(site_id, raw_user_id)

        requested_kwh, requested_available, requested_source = _extract_requested_kwh(raw, delivered_kwh)
        requested_kwh = max(float(requested_kwh), 0.1)

        cap_kwh = max(requested_kwh, delivered_kwh)

        tariff = _deterministic_tariff_fields(site_id, session_id, connection_time)

        expected_tariff = eval_tariff_amount(
            delivered_kwh=delivered_kwh,
            unit_price=tariff["unit_price"],
            mode=tariff["tariff_mode"],
            connection_duration_s=connection_duration_s,
            active_charging_duration_s=active_charging_duration_s,
            parking_duration_s=parking_duration_s,
        )

        original_preauth_limit_t = round(max(0.50, requested_kwh * tariff["unit_price"]), 6)
        valid_preauth_limit_t = round(max(original_preauth_limit_t, expected_tariff.amount * 1.20), 6)

        is_undercap_original = original_preauth_limit_t + 1e-9 < expected_tariff.amount
        topup_delta_recommended = (
            round(max(0.0, expected_tariff.amount * 1.10 - original_preauth_limit_t), 6)
            if is_undercap_original
            else 0.0
        )

        records.append(
            {
                "source": "ACN-Data",
                "source_session_id": session_id,
                "source_site_id": site_id,
                "source_station_id": str(raw_station_id),
                "source_user_id_hash": H_hex(
                    "H_ACN_RAW_USER_HASH",
                    {"site": site_id, "user": str(raw_user_id)},
                )[:16],
                "protocol_user_id": user_id,
                "protocol_station_id": station_id,
                "protocol_meter_id": meter_id,
                "home_domain": "OH_ACN",
                "foreign_domain": _site_domain(site_id),
                "connection_time_utc": connection_time.isoformat(),
                "disconnect_time_utc": disconnect_time.isoformat(),
                "done_charging_time_utc": done_charging_time.isoformat() if done_charging_time is not None else "",
                "tw_start": _to_unix_seconds(connection_time),
                "tw_end": _to_unix_seconds(disconnect_time),
                "connection_duration_s": int(connection_duration_s),
                "active_charging_duration_s": int(active_charging_duration_s),
                "parking_duration_s": int(parking_duration_s),
                "delivered_kwh": round(float(delivered_kwh), 6),
                "requested_kwh": round(float(requested_kwh), 6),
                "requested_kwh_available": bool(requested_available),
                "requested_kwh_source": requested_source,
                "cap_kwh": round(float(cap_kwh), 6),
                "tariff_id": tariff["tariff_id"],
                "tariff_version": tariff["tariff_version"],
                "tariff_mode": tariff["tariff_mode"],
                "tariff_source": tariff["tariff_source"],
                "unit_price": tariff["unit_price"],
                "expected_amount": round(float(expected_tariff.amount), 6),
                "original_preauth_limit_t": original_preauth_limit_t,
                "valid_preauth_limit_t": valid_preauth_limit_t,
                "is_undercap_original": bool(is_undercap_original),
                "topup_delta_recommended": topup_delta_recommended,
                "amount_minus_original_preauth": round(
                    float(expected_tariff.amount - original_preauth_limit_t),
                    6,
                ),
            }
        )

    df = pd.DataFrame.from_records(records)

    if df.empty:
        return df

    df = df.drop_duplicates(subset=["source_site_id", "source_session_id"])
    df = df.sort_values(["connection_time_utc", "source_site_id", "source_session_id"]).reset_index(drop=True)
    df.insert(0, "workload_index", range(len(df)))
    return df


def select_protocol_workload(df_normalized: pd.DataFrame, target_n: int = 5000) -> pd.DataFrame:
    """Select exactly target_n normalized sessions for DBAS-ET workload."""
    if df_normalized.empty:
        raise ValueError("normalized ACN dataframe is empty")

    if len(df_normalized) < target_n:
        raise ValueError(
            f"not enough normalized ACN sessions: have={len(df_normalized)}, target={target_n}. "
            "Increase --oversample-factor, add more --site values, or lower --min-kwh."
        )

    df = df_normalized.head(target_n).copy().reset_index(drop=True)
    df["workload_index"] = range(len(df))
    return df


def _with_profile(df: pd.DataFrame, profile_name: str) -> pd.DataFrame:
    out = df.copy()
    out["profile"] = profile_name

    if profile_name == "valid_preauthorization":
        out["preauth_limit_t"] = out["valid_preauth_limit_t"].astype(float)
    elif profile_name == "original_cap":
        out["preauth_limit_t"] = out["original_preauth_limit_t"].astype(float)
    elif profile_name == "undercap_topup":
        out = out[out["is_undercap_original"] == True].copy()
        out["preauth_limit_t"] = out["original_preauth_limit_t"].astype(float)
    else:
        raise ValueError(f"unknown workload profile: {profile_name}")

    return out.reset_index(drop=True)


def build_workload_profiles(df_workload: pd.DataFrame) -> dict[str, pd.DataFrame]:
    """Build DBAS-ET workload profiles."""
    return {
        "valid_preauthorization": _with_profile(df_workload, "valid_preauthorization"),
        "original_cap": _with_profile(df_workload, "original_cap"),
        "undercap_topup": _with_profile(df_workload, "undercap_topup"),
    }


def write_workload_artifacts(
    df_normalized: pd.DataFrame,
    df_workload: pd.DataFrame,
    profiles: dict[str, pd.DataFrame],
    target_n: int,
    sites: Iterable[str],
    min_energy_kwh: float,
) -> dict[str, Any]:
    """Write normalized workload and profile CSVs."""
    ensure_acn_dirs()

    prefix = workload_cache_prefix(target_n, sites, min_energy_kwh)

    normalized_path = PROCESSED_DIR / f"acn_sessions_normalized_{prefix}.csv"
    workload_path = PROCESSED_DIR / f"dbas_workload_{prefix}.csv"
    valid_path = PROCESSED_DIR / f"profile_valid_preauthorization_{prefix}.csv"
    original_path = PROCESSED_DIR / f"profile_original_cap_{prefix}.csv"
    undercap_path = PROCESSED_DIR / f"profile_undercap_topup_{prefix}.csv"

    # Stable convenience symlinks/copies as default names for downstream scripts.
    normalized_default = PROCESSED_DIR / "acn_sessions_normalized.csv"
    workload_default = PROCESSED_DIR / "dbas_workload_5000.csv"
    valid_default = PROCESSED_DIR / "profile_valid_preauthorization.csv"
    original_default = PROCESSED_DIR / "profile_original_cap.csv"
    undercap_default = PROCESSED_DIR / "profile_undercap_topup.csv"

    df_normalized.to_csv(normalized_path, index=False)
    df_workload.to_csv(workload_path, index=False)
    profiles["valid_preauthorization"].to_csv(valid_path, index=False)
    profiles["original_cap"].to_csv(original_path, index=False)
    profiles["undercap_topup"].to_csv(undercap_path, index=False)

    df_normalized.to_csv(normalized_default, index=False)
    df_workload.to_csv(workload_default, index=False)
    profiles["valid_preauthorization"].to_csv(valid_default, index=False)
    profiles["original_cap"].to_csv(original_default, index=False)
    profiles["undercap_topup"].to_csv(undercap_default, index=False)

    return {
        "normalized_path": str(normalized_path),
        "workload_path": str(workload_path),
        "valid_profile_path": str(valid_path),
        "original_profile_path": str(original_path),
        "undercap_topup_profile_path": str(undercap_path),
        "default_workload_path": str(workload_default),
        "default_valid_profile_path": str(valid_default),
        "default_original_profile_path": str(original_default),
        "default_undercap_topup_profile_path": str(undercap_default),
        "normalized_rows": int(len(df_normalized)),
        "workload_rows": int(len(df_workload)),
        "valid_profile_rows": int(len(profiles["valid_preauthorization"])),
        "original_profile_rows": int(len(profiles["original_cap"])),
        "undercap_topup_rows": int(len(profiles["undercap_topup"])),
    }


def profile_summary_record(
    df_workload: pd.DataFrame,
    profiles: dict[str, pd.DataFrame],
    raw_count: int,
    raw_path: Path,
    artifact_paths: dict[str, Any],
    target_n: int,
    sites: Iterable[str],
    min_energy_kwh: float,
    raw_limit_used: int,
) -> dict[str, Any]:
    """Build one-row workload summary record."""
    undercap = profiles["undercap_topup"]

    return {
        "test_name": "smoke_workload_profiles",
        "source": "ACN-Data",
        "target_n": int(target_n),
        "selected_samples_for_report": int(len(df_workload)),
        "selected_samples_equals_target": int(len(df_workload)) == int(target_n),
        "raw_sessions_cached": int(raw_count),
        "raw_limit_used": int(raw_limit_used),
        "min_energy_kwh": float(min_energy_kwh),
        "requested_sites": ",".join(sites),
        "sites_in_selected_workload": ",".join(sorted(df_workload["source_site_id"].unique())),
        "unique_protocol_users": int(df_workload["protocol_user_id"].nunique()),
        "unique_protocol_stations": int(df_workload["protocol_station_id"].nunique()),
        "unique_protocol_meters": int(df_workload["protocol_meter_id"].nunique()),
        "valid_profile_rows": int(len(profiles["valid_preauthorization"])),
        "original_profile_rows": int(len(profiles["original_cap"])),
        "undercap_topup_rows": int(len(undercap)),
        "undercap_rate_original": round(float(len(undercap) / max(1, len(df_workload))), 6),
        "median_delivered_kwh": round(float(df_workload["delivered_kwh"].median()), 6),
        "p95_delivered_kwh": round(float(df_workload["delivered_kwh"].quantile(0.95)), 6),
        "median_connection_duration_s": round(float(df_workload["connection_duration_s"].median()), 6),
        "median_expected_amount": round(float(df_workload["expected_amount"].median()), 6),
        "median_original_preauth_limit_t": round(float(df_workload["original_preauth_limit_t"].median()), 6),
        "median_valid_preauth_limit_t": round(float(df_workload["valid_preauth_limit_t"].median()), 6),
        "raw_path": str(raw_path),
        **artifact_paths,
        "tariff_note": "deterministic_protocol_tariff_not_acn_billing",
        "payment_semantics": "preauthorized_limit_not_captured_payment",
    }


def read_api_token_from_env_or_file(
    api_token: str | None = None,
    token_file: str | None = None,
) -> str:
    """Read ACN API token from arg, env, or file."""
    if api_token:
        return api_token.strip()

    env_token = os.getenv("ACN_API_TOKEN", "").strip()
    if env_token:
        return env_token

    if token_file:
        path = Path(token_file)
        if path.exists():
            return path.read_text(encoding="utf-8").strip()

    return ""