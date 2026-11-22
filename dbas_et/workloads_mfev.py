from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional, Dict, Any, List

import numpy as np
import pandas as pd


RAW_COLUMN_CANDIDATES = {
    # MFEV raw ChargingRecords.csv does NOT contain an explicit session id.
    # Keep this optional. If missing, we generate a deterministic synthetic id.
    "session_id": [
        "ChargingsessionID",
        "ChargingSessionID",
        "SessionID",
        "session_id",
        "charging_session_id",
    ],
    "user_id": ["UserID", "user_id", "UserId"],
    "charger_id": ["ChargerID", "charger_id", "ChargerId"],
    "charger_company": ["ChargerCompany", "charger_company", "company"],
    "location": ["Location", "location"],
    "charger_type": ["ChargerType", "charger_type"],
    "charger_capacity": ["ChargerCapacity", "charger_capacity", "capacity"],
    "charger_acdc": ["ChargerACDC", "charger_acdc", "ACDC"],
    "start_dt": ["StartDatetime", "SrartDatetime", "start_datetime", "start_dt"],
    "end_dt": ["EndDatetime", "end_datetime", "end_dt"],
    "duration": ["Duration", "duration"],
    "demand": ["Demand", "demand", "energy", "kwh", "kWhDelivered"],
}


def _stable_hash(*parts: object, n: int = 16) -> str:
    s = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:n]


def _find_column(df: pd.DataFrame, candidates: List[str]) -> Optional[str]:
    lower_map = {c.lower(): c for c in df.columns}
    for c in candidates:
        if c in df.columns:
            return c
        if c.lower() in lower_map:
            return lower_map[c.lower()]
    return None


def _read_csv_robust(path: Path) -> pd.DataFrame:
    encodings = ["utf-8", "utf-8-sig", "cp949", "euc-kr", "latin1"]
    last_error = None

    for enc in encodings:
        try:
            return pd.read_csv(path, encoding=enc)
        except Exception as e:
            last_error = e

    raise RuntimeError(f"Cannot read CSV {path}; last_error={last_error}")


def find_mfev_csv(raw_dir: str | Path) -> Path:
    raw_dir = Path(raw_dir)
    candidates = list(raw_dir.rglob("*.csv"))

    if not candidates:
        raise FileNotFoundError(
            f"No CSV found under {raw_dir}. "
            f"Put ChargingRecords.csv there or run scripts/download_mfev_figshare.py."
        )

    best_path = None
    best_score = -1

    for p in candidates:
        try:
            head = _read_csv_robust(p).head(10)
            score = 0
            for names in RAW_COLUMN_CANDIDATES.values():
                if _find_column(head, names) is not None:
                    score += 1
            if score > best_score:
                best_score = score
                best_path = p
        except Exception:
            continue

    if best_path is None:
        raise FileNotFoundError(f"CSV files exist but none could be parsed under {raw_dir}")

    return best_path


def load_raw_mfev(raw_dir: str | Path = "data/raw/mfev") -> pd.DataFrame:
    csv_path = find_mfev_csv(raw_dir)
    print(f"[INFO] using MFEV CSV: {csv_path}")
    return _read_csv_robust(csv_path)


def _make_source_session_id(row: pd.Series, row_index: int) -> str:
    return "MFEV_SESS_" + _stable_hash(
        row_index,
        row.get("user_id_raw", ""),
        row.get("charger_id_raw", ""),
        row.get("start_ts", ""),
        row.get("end_ts", ""),
        row.get("delivered_kwh", ""),
        n=24,
    )


def normalize_mfev_to_dbas(
    raw_df: pd.DataFrame,
    *,
    seed: int = 42,
    valid_margin: float = 1.10,
    undercap_rate: float = 0.025,
    currency: str = "KRW",
) -> pd.DataFrame:
    """
    Convert MFEV ChargingRecords.csv to an ACN-compatible + DBAS-compatible
    workload schema.

    Important:
    - The actual MFEV ChargingRecords.csv may not contain an explicit session id.
    - We generate a deterministic source_session_id/session_id from row content.
    - The output includes ACN-like aliases:
        session_id, connectionTime, disconnectTime, doneChargingTime,
        kWhDelivered, site, station_id, user_id
    - The output also includes DBAS-ET fields:
        trade_id, meter_id, tariff_id, unit_price, cap_kwh,
        preauth_limit_t, preauth_limit_original, etc.
    """

    rng = np.random.default_rng(seed)
    df = raw_df.copy()

    detected: Dict[str, str] = {}
    for key, candidates in RAW_COLUMN_CANDIDATES.items():
        col = _find_column(df, candidates)
        if col is not None:
            detected[key] = col

    # session_id is optional because actual ChargingRecords.csv may not have it.
    must_have = ["user_id", "charger_id", "start_dt", "end_dt", "demand"]
    missing = [k for k in must_have if k not in detected]
    if missing:
        raise ValueError(
            f"Missing required MFEV columns: {missing}. "
            f"Detected columns: {detected}. Raw columns: {list(df.columns)}"
        )

    out = pd.DataFrame()
    out["source_dataset"] = "mfev_scidata_2024"
    out["site"] = "mfev"

    out["user_id_raw"] = df[detected["user_id"]].astype(str)
    out["charger_id_raw"] = df[detected["charger_id"]].astype(str)

    out["start_ts"] = pd.to_datetime(df[detected["start_dt"]], errors="coerce")
    out["end_ts"] = pd.to_datetime(df[detected["end_dt"]], errors="coerce")
    out["delivered_kwh"] = pd.to_numeric(df[deted["demand"]], errors="coerce") if False else pd.to_numeric(df[detected["demand"]], errors="coerce")

    # Optional raw session id; otherwise create deterministic synthetic id later.
    if "session_id" in detected:
        out["source_session_id"] = df[detected["session_id"]].astype(str)
    else:
        out["source_session_id"] = ""

    # Clean invalid rows first.
    out = out.dropna(subset=["start_ts", "end_ts", "delivered_kwh"]).copy()
    out = out[out["delivered_kwh"] > 0].copy()
    out = out[out["end_ts"] > out["start_ts"]].copy()

    # MFEV raw fields.
    if "charger_company" in detected:
        out["operator_raw"] = df.loc[out.index, detected["charger_company"]].astype(str)
    else:
        out["operator_raw"] = "unknown"

    if "location" in detected:
        out["location"] = df.loc[out.index, detected["location"]].astype(str)
    else:
        out["location"] = "unknown"

    if "charger_type" in detected:
        out["charger_type"] = df.loc[out.index, detected["charger_type"]].astype(str)
    else:
        out["charger_type"] = "unknown"

    if "charger_acdc" in detected:
        out["charger_acdc"] = df.loc[out.index, detected["charger_acdc"]].astype(str)
    else:
        # ChargingRecords.csv has no ChargerACDC column.
        # Infer a coarse type from ChargerType if possible.
        out["charger_acdc"] = out["charger_type"].apply(
            lambda x: "DC" if "dc" in str(x).lower() or "fast" in str(x).lower() else "AC"
        )

    if "charger_capacity" in detected:
        out["charger_capacity_kw"] = pd.to_numeric(
            df.loc[out.index, detected["charger_capacity"]],
            errors="coerce",
        )
    else:
        # If absent, keep NaN. Do not invent this as a measured value.
        out["charger_capacity_kw"] = np.nan

    if "duration" in detected:
        out["duration_raw"] = pd.to_numeric(df.loc[out.index, detected["duration"]], errors="coerce")
    else:
        out["duration_raw"] = np.nan

    out = out.reset_index(drop=False).rename(columns={"index": "raw_row_index"})

    # If source_session_id missing, generate deterministic synthetic id from row content.
    missing_sid = out["source_session_id"].astype(str).str.len().eq(0)
    out.loc[missing_sid, "source_session_id"] = out[missing_sid].apply(
        lambda r: _make_source_session_id(r, int(r["raw_row_index"])),
        axis=1,
    )

    # ACN-compatible aliases.
    # Many ACN pipelines expect these names.
    out["session_id"] = out["source_session_id"].astype(str)
    out["connectionTime"] = out["start_ts"]
    out["disconnectTime"] = out["end_ts"]
    out["doneChargingTime"] = out["end_ts"]
    out["kWhDelivered"] = out["delivered_kwh"]
    out["energy_kwh"] = out["delivered_kwh"]
    out["timezone"] = "Asia/Seoul"

    # DBAS pseudonymous IDs.
    out["user_id"] = out["user_id_raw"].apply(lambda x: f"U_MFEV_{_stable_hash(x, n=12)}")
    out["station_id"] = out["charger_id_raw"].apply(lambda x: f"S_MFEV_{_stable_hash(x, n=12)}")
    out["spaceID"] = out["station_id"]
    out["stationID"] = out["station_id"]
    out["evse_id"] = out["station_id"]
    out["meter_id"] = out["station_id"].apply(lambda x: f"M_{x}")

    out["foreign_domain"] = out["operator_raw"].apply(lambda x: f"OF_{_stable_hash(x, n=8)}")
    out["home_domain"] = out["user_id"].apply(lambda x: f"OH_{_stable_hash(x, 'home', n=6)}")
    out["beneficiary"] = out["foreign_domain"].apply(lambda x: f"beneficiary_{x}")

    out["service_type"] = out["charger_acdc"].apply(
        lambda x: "dc_fast_charge" if "dc" in str(x).lower() else "ac_charge"
    )

    # Trade ID bound to ACN-compatible session id + DBAS entities.
    out["trade_id"] = out.apply(
        lambda r: "T_MFEV_" + _stable_hash(
            r["session_id"],
            r["user_id"],
            r["station_id"],
            r["meter_id"],
            r["start_ts"],
            r["end_ts"],
            r["delivered_kwh"],
            n=24,
        ),
        axis=1,
    )

    # Do not use this as final cryptographic sid_t; real protocol should derive sid_t from rho_t.
    # It is only a stable workload-side seed/reference.
    out["sid_seed"] = out.apply(
        lambda r: "SIDSEED_MFEV_" + _stable_hash(
            r["trade_id"],
            r["station_id"],
            r["meter_id"],
            n=24,
        ),
        axis=1,
    )

    # Time window around observed charging interval.
    out["tw_start"] = out["start_ts"] - pd.to_timedelta(15, unit="min")
    out["tw_end"] = out["end_ts"] + pd.to_timedelta(15, unit="min")

    # Authorization energy policy.
    out["requested_kwh"] = out["delivered_kwh"] * rng.uniform(0.98, 1.05, size=len(out))
    out["cap_kwh"] = np.maximum(out["delivered_kwh"] * 1.05, out["requested_kwh"] * 1.02)

    # Deterministic synthetic tariff for settlement benchmark.
    # This is synthetic because MFEV raw ChargingRecords.csv does not include a full
    # DBAS-ready tariff/preauthorization object.
    start_hour = out["start_ts"].dt.hour.fillna(0).astype(int)

    def tariff_mode(hour: int) -> str:
        if hour >= 22 or hour < 8:
            return "off_peak"
        if 11 <= hour < 18:
            return "on_peak"
        return "mid_peak"

    out["tariff_mode"] = start_hour.apply(tariff_mode)

    base_price = {
        "off_peak": 180.0,
        "mid_peak": 240.0,
        "on_peak": 320.0,
    }

    out["unit_price"] = out["tariff_mode"].map(base_price).astype(float)

    # Slightly higher DC/fast charging price.
    dc_mask = out["service_type"].eq("dc_fast_charge")
    out.loc[dc_mask, "unit_price"] *= 1.15

    # Location-specific deterministic factor. Keeps reproducible variation.
    loc_factor = out["location"].astype(str).apply(
        lambda x: 0.95 + (int(_stable_hash(x, n=4), 16) % 21) / 100.0
    )
    out["unit_price"] = (out["unit_price"] * loc_factor).round(6)

    # Preserve raw time-of-use label for analysis, but use ENERGY_ONLY for
    # the current DBAS-ET tariff evaluator.
    out["tariff_mode_raw_mfev"] = out["tariff_mode"]
    out["tariff_mode"] = "ENERGY_ONLY"

    out["currency"] = currency
    out["amount"] = (out["delivered_kwh"] * out["unit_price"]).round(6)

    out["tariff_id"] = out.apply(
        lambda r: "TAR_MFEV_" + _stable_hash(
            r["location"],
            r["charger_type"],
            r["tariff_mode"],
            n=10,
        ),
        axis=1,
    )
    out["tariff_version"] = "mfev_v1"

    # Preauthorization policies.
    out["preauth_limit_valid"] = (out["amount"] * valid_margin).round(6)
    out["preauth_limit_original"] = out["amount"].copy()

    # Controlled under-cap cases for blocked/top-up experiments.
    n_undercap = int(round(len(out) * undercap_rate))
    out["is_undercap_case"] = False

    if n_undercap > 0:
        undercap_idx = rng.choice(out.index.to_numpy(), size=n_undercap, replace=False)
        out.loc[undercap_idx, "is_undercap_case"] = True
        out.loc[undercap_idx, "preauth_limit_original"] = (
            out.loc[undercap_idx, "amount"] *
            rng.uniform(0.70, 0.95, size=len(undercap_idx))
        ).round(6)

    # Default policy for valid benchmark.
    out["preauth_limit_t"] = out["preauth_limit_valid"]

    out["paytok_t"] = f"TOKEN_{currency}"
    out["nonce_u"] = out.apply(lambda r: "NU_" + _stable_hash(r["trade_id"], "u", n=16), axis=1)
    out["nonce_s"] = out.apply(lambda r: "NS_" + _stable_hash(r["trade_id"], "s", n=16), axis=1)
    out["created_at"] = out["start_ts"]

    out["metadata"] = out.apply(
        lambda r: json.dumps(
            {
                "source_dataset": "mfev_scidata_2024",
                "source_session_id": r["source_session_id"],
                "operator_raw": r["operator_raw"],
                "location": r["location"],
                "charger_type": r["charger_type"],
                "charger_acdc": r["charger_acdc"],
                "charger_capacity_kw": None if pd.isna(r["charger_capacity_kw"]) else float(r["charger_capacity_kw"]),
                "currency": currency,
                "synthetic_session_id": str(r["source_session_id"]).startswith("MFEV_SESS_"),
                "synthetic_tariff": True,
                "synthetic_preauth": True,
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
        axis=1,
    )

    # Keep both ACN-compatible and DBAS-compatible columns.
    preferred_cols = [
        # Dataset/source
        "source_dataset",
        "site",
        "raw_row_index",
        "source_session_id",

        # ACN-compatible aliases
        "session_id",
        "connectionTime",
        "disconnectTime",
        "doneChargingTime",
        "kWhDelivered",
        "energy_kwh",
        "timezone",
        "spaceID",
        "stationID",
        "evse_id",

        # DBAS identifiers
        "trade_id",
        "sid_seed",
        "user_id",
        "station_id",
        "meter_id",
        "home_domain",
        "foreign_domain",
        "beneficiary",

        # Service/session
        "service_type",
        "location",
        "charger_type",
        "charger_acdc",
        "charger_capacity_kw",
        "start_ts",
        "end_ts",
        "tw_start",
        "tw_end",

        # Energy/payment
        "delivered_kwh",
        "requested_kwh",
        "cap_kwh",
        "tariff_id",
        "tariff_version",
        "tariff_mode",
        "unit_price",
        "currency",
        "amount",
        "preauth_limit_t",
        "preauth_limit_valid",
        "preauth_limit_original",
        "is_undercap_case",
        "paytok_t",

        # Protocol support
        "nonce_u",
        "nonce_s",
        "created_at",
        "metadata",

        # Raw traceability
        "user_id_raw",
        "charger_id_raw",
        "operator_raw",
        "duration_raw",
    ]

    # Some columns may be absent only if future raw format changes.
    preferred_cols = [c for c in preferred_cols if c in out.columns]
    out = out[preferred_cols].reset_index(drop=True)

    return out


def make_samples(
    df: pd.DataFrame,
    sizes: List[int],
    out_dir: str | Path,
    *,
    seed: int = 42,
    prefix: str = "mfev",
) -> Dict[int, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    paths: Dict[int, Path] = {}

    for n in sizes:
        if n > len(df):
            raise ValueError(f"Requested n={n}, but only {len(df)} cleaned MFEV rows available.")

        sample = df.sample(n=n, random_state=seed).reset_index(drop=True)

        # ACN-compatible filename style.
        out_path = out_dir / f"{prefix}_{n}.csv"
        sample.to_csv(out_path, index=False)

        # Optional alias name for scripts that expect ACN-style naming.
        acn_compat_path = out_dir / f"{prefix}_acn_compatible_{n}.csv"
        sample.to_csv(acn_compat_path, index=False)

        paths[n] = out_path
        print(f"[OK] wrote {n} rows -> {out_path}")
        print(f"[OK] wrote ACN-compatible alias -> {acn_compat_path}")

    return paths


def summarize_workload(df: pd.DataFrame, name: str) -> Dict[str, Any]:
    return {
        "workload": name,
        "rows": int(len(df)),
        "unique_users": int(df["user_id"].nunique()),
        "unique_stations": int(df["station_id"].nunique()),
        "unique_meters": int(df["meter_id"].nunique()),
        "median_kwh": float(df["delivered_kwh"].median()),
        "p95_kwh": float(df["delivered_kwh"].quantile(0.95)),
        "median_amount": float(df["amount"].median()),
        "p95_amount": float(df["amount"].quantile(0.95)),
        "undercap_cases": int(df["is_undercap_case"].sum()),
        "undercap_rate": float(df["is_undercap_case"].mean()),
        "start_min": str(df["start_ts"].min()),
        "start_max": str(df["start_ts"].max()),
    }