from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
PUBLIC_FILE = DATA_DIR / "suspicious_logins_public_v2.csv"
MANIFEST_FILE = DATA_DIR / "dataset_manifest_v2.json"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    df = pd.read_csv(PUBLIC_FILE, low_memory=False)
    manifest = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))

    assert len(df) == manifest["rows"], "Unexpected row count"
    assert df.shape[1] == manifest["public_column_count"], "Unexpected public column count"
    assert df["event_id"].is_unique, "event_id must be unique"
    assert set(df["provider_suspicious"].dropna().unique()).issubset({0, 1}), "Invalid provider_suspicious values"

    expected_hash = manifest["files"][PUBLIC_FILE.name]["sha256"]
    actual_hash = sha256_file(PUBLIC_FILE)
    assert actual_hash == expected_hash, "Public CSV SHA-256 does not match manifest"

    history_ok = (
        ((df["prior_event_count"] == 0) & (df["history_available"] == 0))
        | ((df["prior_event_count"] > 0) & (df["history_available"] == 1))
    ).all()
    assert history_ok, "history_available is inconsistent with prior_event_count"

    first_event_change = ((df["history_available"] == 0) & (df["country_changed"] == 1)).sum()
    assert first_event_change == 0, "country_changed cannot be 1 on a first observed event"

    print("HEIAuthRisk v2 public release validation passed.")


if __name__ == "__main__":
    main()
