"""
HEIAuthRisk v1 processing pipeline — consolidated 42/50 schema.

Scientific release contract
---------------------------
- public schema: 42 attributes;
- restricted schema: all 42 public attributes + 8 controlled-access fields;
- internal lineage/audit fields are not released as scientific attributes;
- public time is generalized to hourly UTC;
- actor_network_id is public and scoped to a single actor, so network behavior
  can be recomputed without exposing a cross-actor network identifier;
- network/country/authentication diversity windows intended for public
  recomputation use event_time_hour_utc and the published per-actor order;
- exact login-count windows use restricted event_time;
- no behavioral feature uses future events;
- provider_suspicious is a provider-generated binary signal, not attack ground
  truth and not a behavioral input feature.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
import math
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parents[1]
RAW_DIR = BASE_DIR / "data" / "raw"
PROCESSED_DIR = BASE_DIR / "data" / "processed"
RAW_FILE_PATTERN = "suspicious_login_logs*.csv"

PUBLIC_FILE = PROCESSED_DIR / "HEIAuthRisk_public_v1.csv"
RESTRICTED_FILE = PROCESSED_DIR / "HEIAuthRisk_restricted_v1.csv"
MANIFEST_FILE = PROCESSED_DIR / "dataset_manifest_v1.json"

DATASET_VERSION = "1.0"
SCHEMA_VERSION = "1.0"
CANONICAL_ORDERING = "actor_pseudo_id_asc_then_event_time_utc_asc_then_event_id_asc"
RELEASE_ORDERING = "event_time_utc_asc_then_event_id_asc"

EXPECTED_PUBLIC_COLUMNS = 42
EXPECTED_RESTRICTED_COLUMNS = 50

load_dotenv(BASE_DIR / ".env")


# ---------------------------------------------------------------------------
# Pseudonymization and identifiers
# ---------------------------------------------------------------------------

def env_var_name_for_institution(folder_name: str) -> str:
    safe = "".join(c.upper() if c.isalnum() else "_" for c in folder_name)
    return f"HMAC_SECRET_KEY_{safe}"


def hmac_hex(value: str, key_bytes: bytes, length: int = 16) -> str:
    return hmac.new(
        key_bytes,
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:length]


def pseudonymize(value, key_bytes: bytes, prefix: str, length: int = 16):
    if pd.isna(value) or value in (None, ""):
        return pd.NA
    return prefix + hmac_hex(str(value), key_bytes, length)


def actor_scoped_network_id(actor_source, ip_source, key_bytes: bytes):
    """Public network identifier stable only inside the same actor.

    The actor source value is included in the HMAC payload, so the same source
    IP observed for two different actors produces unrelated identifiers.
    """
    if pd.isna(actor_source) or pd.isna(ip_source):
        return pd.NA
    payload = f"actor_network\x1f{actor_source}\x1f{ip_source}"
    return "AN" + hmac_hex(payload, key_bytes, 16)


def _canonical_event_value(value) -> str:
    """Canonical string representation used only to build event_id."""
    if value is None or value is pd.NA:
        return "<NA>"
    try:
        if pd.isna(value):
            return "<NA>"
    except (TypeError, ValueError):
        pass

    if isinstance(value, (float, np.floating)):
        return format(float(value), ".17g")
    return str(value).strip()


def build_event_ids(df: pd.DataFrame, event_columns) -> list[str]:
    """Bulk HMAC event IDs without slow DataFrame.apply row objects."""
    cols = sorted(event_columns)
    values = df[cols].to_numpy(dtype=object)
    keys = df["_hmac_key_bytes"].to_numpy(dtype=object)
    out = []
    for row_values, key in zip(values, keys):
        payload = "\x1f".join(
            f"{col}={_canonical_event_value(value)}"
            for col, value in zip(cols, row_values)
        )
        out.append("E" + hmac_hex(payload, key, 32))
    return out


def institution_pseudo_id(folder_name: str, key_bytes: bytes) -> str:
    return "I" + hmac_hex(folder_name, key_bytes, 10)


# ---------------------------------------------------------------------------
# Input discovery and normalization
# ---------------------------------------------------------------------------

def discover_raw_files_with_keys():
    if not RAW_DIR.exists():
        raise FileNotFoundError(f"Raw directory not found: {RAW_DIR}")

    subdirs = sorted(p for p in RAW_DIR.iterdir() if p.is_dir())

    if subdirs:
        pairs = []
        for subdir in subdirs:
            env_name = env_var_name_for_institution(subdir.name)
            key = os.environ.get(env_name)
            if not key:
                raise RuntimeError(
                    f"{env_name} is not set for {subdir.name}. "
                    "Each institution must have its own HMAC key."
                )
            key_bytes = key.encode("utf-8")
            files = sorted(subdir.glob(RAW_FILE_PATTERN))
            if not files:
                print(f"WARNING: no raw CSVs found under {subdir}")
            for path in files:
                pairs.append((path, key_bytes, subdir.name))
        return pairs

    key = os.environ.get("HMAC_SECRET_KEY")
    if not key:
        raise RuntimeError(
            "HMAC_SECRET_KEY is not set. For multiple institutions, use "
            "subdirectories and HMAC_SECRET_KEY_<INSTITUTION>."
        )
    key_bytes = key.encode("utf-8")
    return [
        (p, key_bytes, "single_institution")
        for p in sorted(RAW_DIR.glob(RAW_FILE_PATTERN))
    ]


def read_raw_csv(path: Path) -> pd.DataFrame:
    """Defensive CSV loader with per-file delimiter/encoding detection."""
    last_error = None
    for encoding in ("utf-8", "cp1252", "latin-1"):
        try:
            with path.open("r", encoding=encoding, errors="strict", newline="") as fh:
                sample = fh.read(8192)
            try:
                delimiter = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
            except csv.Error:
                first_line = sample.splitlines()[0] if sample else ""
                delimiter = ";" if first_line.count(";") > first_line.count(",") else ","

            frame = pd.read_csv(path, sep=delimiter, encoding=encoding, low_memory=False)
            if encoding != "utf-8":
                print(f"NOTE: {path.name} decoded as {encoding}")
            return frame
        except Exception as exc:
            last_error = exc
    raise ValueError(f"Could not parse {path}: {last_error}")


def normalize_numeric_column(series: pd.Series) -> pd.Series:
    return pd.to_numeric(
        series.astype(str).str.replace(",", ".", regex=False),
        errors="coerce",
    )


def valid_latitude(value) -> bool:
    return pd.notna(value) and -90 <= float(value) <= 90


def valid_longitude(value) -> bool:
    return pd.notna(value) and -180 <= float(value) <= 180


def sanitize_coordinates(df: pd.DataFrame) -> pd.DataFrame:
    if "latitude" in df.columns:
        df["latitude"] = normalize_numeric_column(df["latitude"])
    if "longitude" in df.columns:
        df["longitude"] = normalize_numeric_column(df["longitude"])

    if {"latitude", "longitude"}.issubset(df.columns):
        out_of_range = (
            df["latitude"].notna() & ~df["latitude"].between(-90, 90)
        ) | (
            df["longitude"].notna() & ~df["longitude"].between(-180, 180)
        )
        if out_of_range.any():
            print(
                f"WARNING: {int(out_of_range.sum())} row(s) contain out-of-range "
                "coordinates; latitude/longitude set to NA."
            )
            df.loc[out_of_range, ["latitude", "longitude"]] = np.nan

        incomplete_pair = df["latitude"].isna() ^ df["longitude"].isna()
        if incomplete_pair.any():
            print(
                f"NOTE: {int(incomplete_pair.sum())} row(s) contain an incomplete "
                "coordinate pair; both coordinates set to NA."
            )
            df.loc[incomplete_pair, ["latitude", "longitude"]] = np.nan
    return df


COUNTRY_NAME_CANONICAL = {
    "The Netherlands": "Netherlands",
}

# Versioned mapping for every normalized country observed in SuspiciousLogin v1.
# The pipeline fails on a new non-null country until this deterministic mapping
# is explicitly extended, preventing silent continent misclassification.
COUNTRY_TO_CONTINENT_v1 = {
    "Albania": "Europe",
    "Angola": "Africa",
    "Australia": "Oceania",
    "Brazil": "South America",
    "Canada": "North America",
    "Czechia": "Europe",
    "Egypt": "Africa",
    "France": "Europe",
    "Germany": "Europe",
    "Japan": "Asia",
    "Namibia": "Africa",
    "Netherlands": "Europe",
    "Poland": "Europe",
    "Portugal": "Europe",
    "Romania": "Europe",
    "Serbia": "Europe",
    "South Africa": "Africa",
    "Spain": "Europe",
    "Switzerland": "Europe",
    "Tunisia": "Africa",
    "United Arab Emirates": "Asia",
    "United Kingdom": "Europe",
    "United States": "North America",
}


def normalize_countries(df: pd.DataFrame) -> pd.DataFrame:
    if "ip_country" in df.columns:
        series = df["ip_country"].astype("string").str.strip()
        series = series.replace({"": pd.NA})
        df["ip_country"] = series.replace(COUNTRY_NAME_CANONICAL)
    return df


def derive_continent_from_country(series: pd.Series) -> pd.Series:
    result = series.map(COUNTRY_TO_CONTINENT_v1).astype("string")
    unknown = series.notna() & result.isna()
    if unknown.any():
        values = sorted(series.loc[unknown].astype(str).unique().tolist())
        raise RuntimeError(
            "Unmapped ip_country value(s) for deterministic continent derivation: "
            f"{values}. Extend COUNTRY_TO_CONTINENT_v1 explicitly before release."
        )
    return result


def normalize_text_field(series: pd.Series) -> pd.Series:
    out = series.astype("string").str.strip()
    return out.replace({"": pd.NA})


def dedupe_pipe_field(value):
    if pd.isna(value):
        return pd.NA
    parts = [p.strip() for p in str(value).split("|") if p.strip()]
    seen, out = set(), []
    for part in parts:
        if part not in seen:
            seen.add(part)
            out.append(part)
    return "|".join(out) if out else pd.NA


def challenge_tokens(value) -> tuple[str, ...] | None:
    if pd.isna(value):
        return None
    parts = [p.strip() for p in str(value).split("|") if p.strip()]
    return tuple(dict.fromkeys(parts)) if parts else None


def challenge_signature(value):
    tokens = challenge_tokens(value)
    if not tokens:
        return pd.NA
    return "|".join(sorted(set(tokens)))


# ---------------------------------------------------------------------------
# Generic behavioral feature helpers
# ---------------------------------------------------------------------------

def is_first_occurrence_for_user(df: pd.DataFrame, value_col: str) -> pd.Series:
    valid = df[value_col].notna()
    duplicated = df.duplicated(
        subset=["actor_pseudo_id", value_col],
        keep="first",
    )
    out = pd.Series(pd.NA, index=df.index, dtype="Int64")
    out.loc[valid] = (~duplicated.loc[valid]).astype("int64")
    return out


def changed_from_previous(df: pd.DataFrame, value_col: str) -> pd.Series:
    previous = df.groupby("actor_pseudo_id", sort=False)[value_col].shift(1)
    first = df["prior_event_count"].eq(0)
    out = pd.Series(pd.NA, index=df.index, dtype="Int64")
    out.loc[first] = 0
    comparable = (~first) & df[value_col].notna() & previous.notna()
    out.loc[comparable] = (
        df.loc[comparable, value_col].astype("object").to_numpy()
        != previous.loc[comparable].astype("object").to_numpy()
    ).astype("int64")
    return out


def cumulative_distinct_for_user(df: pd.DataFrame, value_col: str) -> pd.Series:
    out = pd.Series(0, index=df.index, dtype="Int64")
    for _, group in df.groupby("actor_pseudo_id", sort=False):
        seen = set()
        for idx, value in group[value_col].items():
            if pd.notna(value):
                seen.add(str(value))
            out.at[idx] = len(seen)
    return out


def rolling_distinct_public_scalar_window(
    df: pd.DataFrame,
    value_col: str,
    window: pd.Timedelta,
    time_col: str = "event_time_hour_utc",
) -> pd.Series:
    """Distinct known scalar values in [t-window, t] using published order."""
    required = list(dict.fromkeys([
        "actor_pseudo_id", "prior_event_count", time_col, value_col,
    ]))
    work = df[required].sort_values(
        ["actor_pseudo_id", "prior_event_count"]
    )

    indices = work.index.to_numpy()
    groups = work["actor_pseudo_id"].astype("object").to_numpy()
    times = (
        pd.to_datetime(work[time_col], utc=True)
        .dt.tz_convert(None)
        .to_numpy(dtype="datetime64[ns]")
        .astype("int64")
    )
    values = work[value_col].astype("object").to_numpy()
    out = np.zeros(len(work), dtype=np.int64)
    window_ns = int(
        window.to_timedelta64().astype("timedelta64[ns]").astype("int64")
    )

    start = 0
    n = len(work)
    while start < n:
        end = start + 1
        while end < n and groups[end] == groups[start]:
            end += 1

        actor_times = times[start:end]
        if len(actor_times) > 1 and np.any(actor_times[1:] < actor_times[:-1]):
            raise RuntimeError(
                f"Non-monotonic {time_col} for actor {groups[start]}"
            )

        counts = Counter()
        left = start
        for right in range(start, end):
            cutoff = times[right] - window_ns
            while left <= right and times[left] < cutoff:
                old = values[left]
                if not pd.isna(old):
                    key = str(old)
                    counts[key] -= 1
                    if counts[key] <= 0:
                        del counts[key]
                left += 1

            value = values[right]
            if not pd.isna(value):
                counts[str(value)] += 1
            out[right] = len(counts)

        start = end

    result = pd.Series(index=indices, data=pd.array(out, dtype="Int64"))
    return result.reindex(df.index)


def rolling_distinct_public_token_window(
    df: pd.DataFrame,
    value_col: str,
    window: pd.Timedelta,
    time_col: str = "event_time_hour_utc",
) -> pd.Series:
    """Distinct individual pipe-delimited tokens in [t-window, t]."""
    required = list(dict.fromkeys([
        "actor_pseudo_id", "prior_event_count", time_col, value_col,
    ]))
    work = df[required].sort_values(
        ["actor_pseudo_id", "prior_event_count"]
    )

    indices = work.index.to_numpy()
    groups = work["actor_pseudo_id"].astype("object").to_numpy()
    times = (
        pd.to_datetime(work[time_col], utc=True)
        .dt.tz_convert(None)
        .to_numpy(dtype="datetime64[ns]")
        .astype("int64")
    )
    token_rows = [challenge_tokens(v) or tuple() for v in work[value_col]]
    out = np.zeros(len(work), dtype=np.int64)
    window_ns = int(
        window.to_timedelta64().astype("timedelta64[ns]").astype("int64")
    )

    start = 0
    n = len(work)
    while start < n:
        end = start + 1
        while end < n and groups[end] == groups[start]:
            end += 1

        counts = Counter()
        left = start
        for right in range(start, end):
            cutoff = times[right] - window_ns
            while left <= right and times[left] < cutoff:
                for token in token_rows[left]:
                    counts[token] -= 1
                    if counts[token] <= 0:
                        del counts[token]
                left += 1

            for token in token_rows[right]:
                counts[token] += 1
            out[right] = len(counts)

        start = end

    result = pd.Series(index=indices, data=pd.array(out, dtype="Int64"))
    return result.reindex(df.index)


def is_new_challenge_for_user(df: pd.DataFrame) -> pd.Series:
    out = pd.Series(pd.NA, index=df.index, dtype="Int64")
    for _, group in df.groupby("actor_pseudo_id", sort=False):
        seen = set()
        for idx, value in group["login_challenge_method"].items():
            tokens = challenge_tokens(value)
            if tokens is None:
                continue
            current = set(tokens)
            out.at[idx] = int(bool(current - seen))
            seen.update(current)
    return out


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_provider_signal(series: pd.Series) -> pd.Series:
    """Normalize provider signal and enforce the binary release contract."""
    normalized = series.astype("string").str.strip().str.lower()
    mapped = normalized.map({
        "true": 1, "1": 1, "yes": 1,
        "false": 0, "0": 0, "no": 0,
    })

    invalid = mapped.isna()
    if invalid.any():
        examples = sorted(normalized.loc[invalid].dropna().unique().tolist())[:10]
        raise RuntimeError(
            "provider_suspicious must be binary for every retained event; "
            f"found {int(invalid.sum())} unmapped/missing value(s). "
            f"Examples={examples}"
        )
    return mapped.astype("Int64")


# ---------------------------------------------------------------------------
# Load and clean raw files
# ---------------------------------------------------------------------------
raw_files = discover_raw_files_with_keys()
if not raw_files:
    raise FileNotFoundError(f"No raw files found under {RAW_DIR}")

frames = []
expected_columns = None
removed_empty_rows = 0
print(f"Found {len(raw_files)} raw file(s).")

for path, key_bytes, institution_name in raw_files:
    frame = read_raw_csv(path)

    empty_rows = frame.isna().all(axis=1)
    if empty_rows.any():
        n_empty = int(empty_rows.sum())
        removed_empty_rows += n_empty
        print(f"REMOVED: {n_empty} completely empty row(s) from {path.name}")
        frame = frame.loc[~empty_rows].copy()

    if expected_columns is None:
        expected_columns = set(frame.columns)
    elif set(frame.columns) != expected_columns:
        missing = sorted(expected_columns - set(frame.columns))
        extra = sorted(set(frame.columns) - expected_columns)
        raise ValueError(
            f"{path.name} has a different raw schema. Missing={missing}; Extra={extra}"
        )

    frame["_source_file"] = path.name
    frame["_institution_name_internal"] = institution_name
    frame["_hmac_key_bytes"] = [key_bytes] * len(frame)
    frames.append(frame)

df = pd.concat(frames, ignore_index=True)
df["_stable_row_order"] = np.arange(len(df), dtype=np.int64)

required = {
    "event_time", "actor_email_hash", "ip_hash", "is_suspicious",
    "login_type", "login_challenge_method", "ip_country", "ip_version",
}
missing_required = required - set(df.columns)
if missing_required:
    raise ValueError(f"Missing required raw column(s): {sorted(missing_required)}")

# Rows without exact time or actor identity cannot participate in the sequence.
df["event_time"] = pd.to_datetime(df["event_time"], utc=True, errors="coerce")
invalid_core = df["event_time"].isna() | df["actor_email_hash"].isna()
removed_invalid_core_rows = int(invalid_core.sum())
if invalid_core.any():
    print(
        f"REMOVED: {removed_invalid_core_rows} row(s) missing/invalid event_time "
        "or actor_email_hash."
    )
    df = df.loc[~invalid_core].copy().reset_index(drop=True)

df = sanitize_coordinates(df)
df = normalize_countries(df)

if "ip_version" in df.columns:
    df["ip_version"] = normalize_numeric_column(df["ip_version"]).astype("Int64")
    invalid_ip_version = ~df["ip_version"].isin([4, 6]) & df["ip_version"].notna()
    if invalid_ip_version.any():
        print(
            f"WARNING: {int(invalid_ip_version.sum())} row(s) have invalid "
            "ip_version; set to NA."
        )
        df.loc[invalid_ip_version, "ip_version"] = pd.NA

# Preserve the established content-based deduplication contract before release
# normalization of categorical fields.
content_columns = [
    c for c in df.columns
    if c not in {
        "record_id", "_source_file", "_institution_name_internal",
        "_hmac_key_bytes", "_stable_row_order",
    }
]

before = len(df)
df = df.drop_duplicates(subset=content_columns, keep="first").reset_index(drop=True)
removed_duplicate_rows = before - len(df)
print(f"Removed duplicate rows: {removed_duplicate_rows}")
df["_stable_row_order"] = np.arange(len(df), dtype=np.int64)

# ---------------------------------------------------------------------------
# Pseudonyms and event identifiers
# ---------------------------------------------------------------------------
df["actor_pseudo_id"] = [
    pseudonymize(v, k, "U", 16)
    for v, k in zip(df["actor_email_hash"], df["_hmac_key_bytes"])
]

df["network_pseudo_id"] = [
    pseudonymize(v, k, "N", 16)
    for v, k in zip(df["ip_hash"], df["_hmac_key_bytes"])
]

df["actor_network_id"] = [
    actor_scoped_network_id(actor, ip, key)
    for actor, ip, key in zip(
        df["actor_email_hash"], df["ip_hash"], df["_hmac_key_bytes"]
    )
]

df["institution_pseudo_id"] = [
    institution_pseudo_id(n, k)
    for n, k in zip(df["_institution_name_internal"], df["_hmac_key_bytes"])
]

event_id_columns = tuple(sorted(content_columns))
df["event_id"] = build_event_ids(df, event_id_columns)

if df["event_id"].duplicated().any():
    dup_mask = df["event_id"].duplicated(keep=False)
    raise RuntimeError(
        "Duplicate/colliding event_id detected after content deduplication: "
        f"{int(dup_mask.sum())} row(s). Inspect before publication."
    )

# Release-normalized categorical fields.
df["login_type"] = normalize_text_field(df["login_type"])
df["login_challenge_method"] = df["login_challenge_method"].map(dedupe_pipe_field)
df["continent"] = derive_continent_from_country(df["ip_country"])
df["provider_suspicious"] = normalize_provider_signal(df["is_suspicious"])

# ---------------------------------------------------------------------------
# Canonical per-actor order and temporal features
# ---------------------------------------------------------------------------
df["event_time_hour_utc"] = df["event_time"].dt.floor("h")

df = df.sort_values(
    ["actor_pseudo_id", "event_time", "event_id"],
    na_position="last",
).reset_index(drop=True)

df["prior_event_count"] = df.groupby("actor_pseudo_id", sort=False).cumcount().astype("Int64")

# Block A — temporal
df["event_hour"] = df["event_time_hour_utc"].dt.hour.astype("Int64")
df["day_of_week"] = df["event_time_hour_utc"].dt.day_of_week.astype("Int64")
df["month"] = df["event_time_hour_utc"].dt.month.astype("Int64")
df["is_weekend"] = df["day_of_week"].isin([5, 6]).astype("Int64")

# Block B — activity and history
df["hours_since_last_login"] = (
    df.groupby("actor_pseudo_id", sort=False)["event_time"]
      .diff().dt.total_seconds().div(3600).round(4)
)

first_time = df.groupby("actor_pseudo_id", sort=False)["event_time"].transform("min")
df["hours_since_first_login"] = (
    (df["event_time"] - first_time).dt.total_seconds() / 3600.0
).round(4)

for col in ("logins_24h", "logins_7d", "logins_30d"):
    df[col] = pd.Series(pd.NA, index=df.index, dtype="Int64")

window_map = {
    "logins_24h": np.timedelta64(24, "h"),
    "logins_7d": np.timedelta64(7, "D"),
    "logins_30d": np.timedelta64(30, "D"),
}

for _, group in df.groupby("actor_pseudo_id", sort=False):
    times = group["event_time"].dt.tz_convert(None).to_numpy(dtype="datetime64[ns]")
    for col, delta in window_map.items():
        left = np.searchsorted(times, times - delta, side="left")
        counts = np.arange(len(times)) + 1 - left
        df.loc[group.index, col] = pd.array(counts, dtype="Int64")

current_date = df["event_time_hour_utc"].dt.floor("D")
first_date = first_time.dt.floor("D")
observed_calendar_days_30d = (
    (current_date - first_date).dt.days.add(1).clip(upper=30).astype("Int64")
)
df["login_rate_30d"] = (
    df["logins_30d"].astype(float) / observed_calendar_days_30d.astype(float)
).round(6)

df["_event_date_utc"] = current_date
df["active_days_30d"] = rolling_distinct_public_scalar_window(
    df,
    value_col="_event_date_utc",
    time_col="_event_date_utc",
    window=pd.Timedelta(days=29),
)

# ---------------------------------------------------------------------------
# Block C — network/IP
# ---------------------------------------------------------------------------
df["is_new_ip"] = is_first_occurrence_for_user(df, "actor_network_id")
df["ip_changed"] = changed_from_previous(df, "actor_network_id")

df["distinct_networks_24h"] = rolling_distinct_public_scalar_window(
    df, "actor_network_id", pd.Timedelta(hours=24)
)
df["distinct_networks_7d"] = rolling_distinct_public_scalar_window(
    df, "actor_network_id", pd.Timedelta(days=7)
)
df["distinct_networks_30d"] = rolling_distinct_public_scalar_window(
    df, "actor_network_id", pd.Timedelta(days=30)
)
df["networks_seen_to_date"] = cumulative_distinct_for_user(df, "actor_network_id")

# ---------------------------------------------------------------------------
# Block D — geography
# ---------------------------------------------------------------------------
df["is_new_country"] = is_first_occurrence_for_user(df, "ip_country")
df["country_changed"] = changed_from_previous(df, "ip_country")
df["is_new_continent"] = is_first_occurrence_for_user(df, "continent")
df["continent_changed"] = changed_from_previous(df, "continent")

df["distinct_countries_24h"] = rolling_distinct_public_scalar_window(
    df, "ip_country", pd.Timedelta(hours=24)
)
df["distinct_countries_7d"] = rolling_distinct_public_scalar_window(
    df, "ip_country", pd.Timedelta(days=7)
)
df["distinct_countries_30d"] = rolling_distinct_public_scalar_window(
    df, "ip_country", pd.Timedelta(days=30)
)
df["distinct_countries_to_date"] = cumulative_distinct_for_user(df, "ip_country")

# ---------------------------------------------------------------------------
# Block E — authentication
# ---------------------------------------------------------------------------
df["is_new_login_type"] = is_first_occurrence_for_user(df, "login_type")
df["login_type_changed"] = changed_from_previous(df, "login_type")

df["is_new_challenge"] = is_new_challenge_for_user(df)
df["_challenge_signature"] = df["login_challenge_method"].map(challenge_signature)
df["challenge_changed"] = changed_from_previous(df, "_challenge_signature")

df["distinct_login_types_30d"] = rolling_distinct_public_scalar_window(
    df, "login_type", pd.Timedelta(days=30)
)
df["distinct_challenges_30d"] = rolling_distinct_public_token_window(
    df, "login_challenge_method", pd.Timedelta(days=30)
)

# ---------------------------------------------------------------------------
# Restricted mobility features
# ---------------------------------------------------------------------------
df["travel_distance_km"] = np.nan
df["travel_speed_kmh"] = np.nan

if {"latitude", "longitude"}.issubset(df.columns):
    prev_lat = df.groupby("actor_pseudo_id", sort=False)["latitude"].shift(1)
    prev_lon = df.groupby("actor_pseudo_id", sort=False)["longitude"].shift(1)

    valid = (
        df["prior_event_count"].gt(0)
        & prev_lat.notna() & prev_lon.notna()
        & df["latitude"].notna() & df["longitude"].notna()
    )

    if valid.any():
        lat1 = np.radians(prev_lat.loc[valid].astype(float).to_numpy())
        lon1 = np.radians(prev_lon.loc[valid].astype(float).to_numpy())
        lat2 = np.radians(df.loc[valid, "latitude"].astype(float).to_numpy())
        lon2 = np.radians(df.loc[valid, "longitude"].astype(float).to_numpy())
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = (
            np.sin(dlat / 2) ** 2
            + np.cos(lat1) * np.cos(lat2) * np.sin(dlon / 2) ** 2
        )
        distances = 2 * 6371.0088 * np.arcsin(np.minimum(1.0, np.sqrt(a)))
        df.loc[valid, "travel_distance_km"] = distances

        hours = df.loc[valid, "hours_since_last_login"].astype(float)
        speed_valid = hours.gt(0)
        speed_index = hours.index[speed_valid]
        df.loc[speed_index, "travel_speed_kmh"] = (
            df.loc[speed_index, "travel_distance_km"] / hours.loc[speed_index]
        )

    # Output precision only; does not alter the feature definition.
    df["travel_distance_km"] = df["travel_distance_km"].round(2)
    df["travel_speed_kmh"] = df["travel_speed_kmh"].round(2)

# ---------------------------------------------------------------------------
# Canonical global release order
# ---------------------------------------------------------------------------
df = df.sort_values(
    ["event_time", "event_id"],
    ascending=[True, True],
).reset_index(drop=True)

PUBLIC_COLUMNS = [
    "event_id",
    "actor_pseudo_id",
    "event_time_hour_utc",
    "event_hour",
    "day_of_week",
    "month",
    "is_weekend",
    "prior_event_count",
    "hours_since_last_login",
    "hours_since_first_login",
    "logins_24h",
    "logins_7d",
    "logins_30d",
    "login_rate_30d",
    "active_days_30d",
    "actor_network_id",
    "ip_version",
    "is_new_ip",
    "ip_changed",
    "distinct_networks_24h",
    "distinct_networks_7d",
    "distinct_networks_30d",
    "networks_seen_to_date",
    "ip_country",
    "continent",
    "is_new_country",
    "country_changed",
    "is_new_continent",
    "continent_changed",
    "distinct_countries_24h",
    "distinct_countries_7d",
    "distinct_countries_30d",
    "distinct_countries_to_date",
    "login_type",
    "login_challenge_method",
    "is_new_login_type",
    "login_type_changed",
    "is_new_challenge",
    "challenge_changed",
    "distinct_login_types_30d",
    "distinct_challenges_30d",
    "provider_suspicious",
]

RESTRICTED_ADDITIONAL_COLUMNS = [
    "event_time",
    "institution_pseudo_id",
    "network_pseudo_id",
    "ip_city",
    "latitude",
    "longitude",
    "travel_distance_km",
    "travel_speed_kmh",
]

public_dataset = df[PUBLIC_COLUMNS].copy()
restricted_dataset = df[PUBLIC_COLUMNS + RESTRICTED_ADDITIONAL_COLUMNS].copy()

# ---------------------------------------------------------------------------
# Release invariants
# ---------------------------------------------------------------------------
assert len(PUBLIC_COLUMNS) == EXPECTED_PUBLIC_COLUMNS
assert len(RESTRICTED_ADDITIONAL_COLUMNS) == 8
assert len(public_dataset.columns) == EXPECTED_PUBLIC_COLUMNS
assert len(restricted_dataset.columns) == EXPECTED_RESTRICTED_COLUMNS
assert len(public_dataset) == len(restricted_dataset)
assert public_dataset["event_id"].is_unique
assert restricted_dataset["event_id"].is_unique
assert public_dataset["event_id"].tolist() == restricted_dataset["event_id"].tolist()
assert restricted_dataset["event_time"].is_monotonic_increasing

# Temporal invariants.
assert (public_dataset["event_time_hour_utc"].dt.minute == 0).all()
assert (public_dataset["event_time_hour_utc"].dt.second == 0).all()
assert public_dataset["event_hour"].between(0, 23).all()
assert public_dataset["day_of_week"].between(0, 6).all()
assert public_dataset["month"].between(1, 12).all()
assert set(public_dataset["is_weekend"].dropna().unique()).issubset({0, 1})

# Activity invariants.
assert (public_dataset["prior_event_count"] >= 0).all()
assert (public_dataset["logins_24h"] <= public_dataset["logins_7d"]).all()
assert (public_dataset["logins_7d"] <= public_dataset["logins_30d"]).all()
assert public_dataset["active_days_30d"].between(1, 30).all()
assert (public_dataset["active_days_30d"] <= public_dataset["logins_30d"]).all()
assert (public_dataset["login_rate_30d"] > 0).all()

first_mask = public_dataset["prior_event_count"].eq(0)
assert public_dataset.loc[first_mask, "hours_since_last_login"].isna().all()
assert (public_dataset.loc[first_mask, "hours_since_first_login"] == 0).all()
assert (public_dataset.loc[first_mask, "logins_24h"] == 1).all()
assert (public_dataset.loc[first_mask, "logins_7d"] == 1).all()
assert (public_dataset.loc[first_mask, "logins_30d"] == 1).all()
assert (public_dataset.loc[first_mask, "login_rate_30d"] == 1.0).all()
assert (public_dataset.loc[first_mask, "active_days_30d"] == 1).all()

# Nullable binary domains.
nullable_binary = [
    "is_new_ip", "ip_changed",
    "is_new_country", "country_changed",
    "is_new_continent", "continent_changed",
    "is_new_login_type", "login_type_changed",
    "is_new_challenge", "challenge_changed",
]
for col in nullable_binary:
    assert set(public_dataset[col].dropna().unique()).issubset({0, 1}), col

# Changed flags are 0 for the first event by definition.
for col in [
    "ip_changed", "country_changed", "continent_changed",
    "login_type_changed", "challenge_changed",
]:
    assert (public_dataset.loc[first_mask, col] == 0).all(), col

# Network invariants.
assert (
    public_dataset["distinct_networks_24h"]
    <= public_dataset["distinct_networks_7d"]
).all()
assert (
    public_dataset["distinct_networks_7d"]
    <= public_dataset["distinct_networks_30d"]
).all()
assert (
    public_dataset["distinct_networks_30d"]
    <= public_dataset["networks_seen_to_date"]
).all()
known_network = public_dataset["actor_network_id"].notna()
assert (public_dataset.loc[known_network, "distinct_networks_24h"] >= 1).all()
assert (public_dataset.loc[known_network, "distinct_networks_7d"] >= 1).all()
assert (public_dataset.loc[known_network, "distinct_networks_30d"] >= 1).all()

# actor_network_id must not become a cross-actor join key.
network_actor_counts = (
    public_dataset.loc[known_network]
    .groupby("actor_network_id")["actor_pseudo_id"]
    .nunique()
)
assert (network_actor_counts <= 1).all()

# Geography invariants.
assert (
    public_dataset["distinct_countries_24h"]
    <= public_dataset["distinct_countries_7d"]
).all()
assert (
    public_dataset["distinct_countries_7d"]
    <= public_dataset["distinct_countries_30d"]
).all()
assert (
    public_dataset["distinct_countries_30d"]
    <= public_dataset["distinct_countries_to_date"]
).all()
known_country = public_dataset["ip_country"].notna()
assert public_dataset.loc[known_country, "continent"].notna().all()
assert (public_dataset.loc[known_country, "distinct_countries_24h"] >= 1).all()

# Authentication diversity domains.
assert (public_dataset["distinct_login_types_30d"] >= 0).all()
assert (public_dataset["distinct_challenges_30d"] >= 0).all()

# Provider signal: strictly binary and complete.
assert not public_dataset["provider_suspicious"].isna().any()
assert set(public_dataset["provider_suspicious"].unique()).issubset({0, 1})

# Public-recomputation checks for hourly diversity windows.
recomputed_network_24 = rolling_distinct_public_scalar_window(
    public_dataset, "actor_network_id", pd.Timedelta(hours=24)
)
recomputed_network_7 = rolling_distinct_public_scalar_window(
    public_dataset, "actor_network_id", pd.Timedelta(days=7)
)
recomputed_network_30 = rolling_distinct_public_scalar_window(
    public_dataset, "actor_network_id", pd.Timedelta(days=30)
)
assert recomputed_network_24.equals(public_dataset["distinct_networks_24h"])
assert recomputed_network_7.equals(public_dataset["distinct_networks_7d"])
assert recomputed_network_30.equals(public_dataset["distinct_networks_30d"])

for col, delta in [
    ("distinct_countries_24h", pd.Timedelta(hours=24)),
    ("distinct_countries_7d", pd.Timedelta(days=7)),
    ("distinct_countries_30d", pd.Timedelta(days=30)),
]:
    recomputed = rolling_distinct_public_scalar_window(
        public_dataset, "ip_country", delta
    )
    assert recomputed.equals(public_dataset[col]), col
recomputed_login_types = rolling_distinct_public_scalar_window(
    public_dataset, "login_type", pd.Timedelta(days=30)
)
assert recomputed_login_types.equals(public_dataset["distinct_login_types_30d"])

recomputed_challenges = rolling_distinct_public_token_window(
    public_dataset, "login_challenge_method", pd.Timedelta(days=30)
)
assert recomputed_challenges.equals(public_dataset["distinct_challenges_30d"])

# Restricted coordinate and mobility checks.
if restricted_dataset["latitude"].notna().any():
    assert restricted_dataset["latitude"].dropna().between(-90, 90).all()
if restricted_dataset["longitude"].notna().any():
    assert restricted_dataset["longitude"].dropna().between(-180, 180).all()
assert restricted_dataset["latitude"].isna().equals(restricted_dataset["longitude"].isna())
assert (restricted_dataset["travel_distance_km"].dropna() >= 0).all()
assert (restricted_dataset["travel_speed_kmh"].dropna() >= 0).all()

# Fields that must not leak into the public schema.
for forbidden in RESTRICTED_ADDITIONAL_COLUMNS + [
    "source_file_id", "actor_email_hash", "ip_hash", "ip_region",
    "history_available", "is_impossible_travel",
    "risk_score", "risk_level", "label", "is_attack", "is_anomaly",
]:
    assert forbidden not in public_dataset.columns, forbidden

# Internal/audit-only fields must not be in the restricted scientific schema.
for forbidden in [
    "source_file_id", "actor_email_hash", "ip_hash", "ip_region",
    "history_available", "is_impossible_travel",
    "risk_score", "risk_level", "label", "is_attack", "is_anomaly",
]:
    assert forbidden not in restricted_dataset.columns, forbidden

# ---------------------------------------------------------------------------
# Write release and manifest
# ---------------------------------------------------------------------------
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
public_dataset.to_csv(PUBLIC_FILE, index=False)
restricted_dataset.to_csv(RESTRICTED_FILE, index=False)

provider_positive = int((public_dataset["provider_suspicious"] == 1).sum())
user_event_counts = public_dataset["actor_pseudo_id"].value_counts()

manifest = {
    "dataset_name": "SuspiciousLogin",
    "dataset_version": DATASET_VERSION,
    "schema_version": SCHEMA_VERSION,
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "canonical_actor_ordering": CANONICAL_ORDERING,
    "release_ordering": RELEASE_ORDERING,
    "history_tie_breaker": "event_id_asc_for_equal_actor_and_event_time",
    "timezone": "UTC",
    "time_min": restricted_dataset["event_time"].min().isoformat(),
    "time_max": restricted_dataset["event_time"].max().isoformat(),
    "rows": int(len(public_dataset)),
    "unique_users": int(public_dataset["actor_pseudo_id"].nunique()),
    "singleton_users": int((user_event_counts == 1).sum()),
    "provider_suspicious_domain": [0, 1],
    "provider_suspicious_positive": provider_positive,
    "provider_suspicious_proportion": (
        provider_positive / len(public_dataset) if len(public_dataset) else None
    ),
    "raw_file_count": int(len(raw_files)),
    "removed_empty_rows": int(removed_empty_rows),
    "removed_invalid_core_rows": int(removed_invalid_core_rows),
    "removed_duplicate_rows": int(removed_duplicate_rows),
    "institution_count_restricted": int(
        restricted_dataset["institution_pseudo_id"].nunique()
    ),
    "public_columns": PUBLIC_COLUMNS,
    "restricted_columns": PUBLIC_COLUMNS + RESTRICTED_ADDITIONAL_COLUMNS,
    "public_column_count": EXPECTED_PUBLIC_COLUMNS,
    "restricted_column_count": EXPECTED_RESTRICTED_COLUMNS,
    "actor_network_id_scope": (
        "actor-scoped; stable only within the same actor; not comparable across actors"
    ),
    "public_hourly_diversity_windows": [
        "distinct_networks_24h",
        "distinct_networks_7d",
        "distinct_networks_30d",
        "distinct_countries_24h",
        "distinct_countries_7d",
        "distinct_countries_30d",
        "distinct_login_types_30d",
        "distinct_challenges_30d",
    ],
    "exact_time_features": [
        "hours_since_last_login",
        "hours_since_first_login",
        "logins_24h",
        "logins_7d",
        "logins_30d",
        "travel_distance_km",
        "travel_speed_kmh",
    ],
    "country_policy": (
        "normalized ip_country preserved; continent deterministically derived; "
        "no release-time rare-country grouping"
    ),
    "continent_mapping": "COUNTRY_TO_CONTINENT_v1 embedded versioned mapping",
    "internal_fields_not_released": [
        "source_file_id",
        "actor_email_hash",
        "ip_hash",
        "ip_region",
    ],
    "excluded_core_features": [
        "history_available",
        "is_impossible_travel",
        "is_night_login",
        "is_business_hours",
        "geo_jump",
        "risk_score",
        "risk_level",
        "label",
        "is_attack",
        "is_anomaly",
    ],
    "files": {
        PUBLIC_FILE.name: {
            "sha256": sha256_file(PUBLIC_FILE),
            "rows": int(len(public_dataset)),
            "columns": EXPECTED_PUBLIC_COLUMNS,
        },
        RESTRICTED_FILE.name: {
            "sha256": sha256_file(RESTRICTED_FILE),
            "rows": int(len(restricted_dataset)),
            "columns": EXPECTED_RESTRICTED_COLUMNS,
        },
    },
}

with MANIFEST_FILE.open("w", encoding="utf-8") as fh:
    json.dump(manifest, fh, ensure_ascii=False, indent=2)

print("SuspiciousLogin v1 processing complete.")
print(f"Canonical actor ordering: {CANONICAL_ORDERING}")
print(f"Release ordering: {RELEASE_ORDERING}")
print(
    f"Public: {PUBLIC_FILE} -> {len(public_dataset):,} rows, "
    f"{len(public_dataset.columns)} columns"
)
print(
    f"Restricted: {RESTRICTED_FILE} -> {len(restricted_dataset):,} rows, "
    f"{len(restricted_dataset.columns)} columns"
)
print(f"Manifest: {MANIFEST_FILE}")
print("provider_suspicious domain: binary {0, 1}")
