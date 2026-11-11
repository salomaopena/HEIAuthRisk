#!/usr/bin/env python3
"""Create an actor-preserving demo sample from HEIAuthRisk."""

from __future__ import annotations

import argparse
from pathlib import Path


import numpy as np
import pandas as pd

REQUIRED_COLUMNS = {
    "event_id",
    "actor_pseudo_id",
    "prior_event_count",
    "provider_suspicious",
}
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = (
    BASE_DIR
    / "data"
    / "processed"
    / "suspicious_logins_restricted_v2.csv"
)

DEFAULT_OUTPUT = (
    BASE_DIR
    / "data"
    / "processed"
    / "suspicious_logins_restricted_demo_sample.csv"
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Create an actor-preserving demo sample from HEIAuthRisk."
    )
    p.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--min-events", type=int, default=300)
    p.add_argument("--target-events", type=int, default=400)
    p.add_argument("--max-events", type=int, default=500)
    p.add_argument("--min-actor-events", type=int, default=2)
    p.add_argument("--max-actor-events", type=int, default=20)
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if not (0 < args.min_events <= args.target_events <= args.max_events):
        raise ValueError("Expected 0 < min-events <= target-events <= max-events")
    if not (1 <= args.min_actor_events <= args.max_actor_events):
        raise ValueError("Expected 1 <= min-actor-events <= max-actor-events")


def load_public_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(path)
    df = pd.read_csv(path, low_memory=False)
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")
    if not df["event_id"].is_unique:
        raise ValueError("event_id must be unique in the source dataset")
    if "history_available" in df.columns:
        raise ValueError("history_available must not exist in the v2.0 public schema")
    return df


def summarize_actors(df: pd.DataFrame) -> pd.DataFrame:
    return (
        df.groupby("actor_pseudo_id", sort=False)
        .agg(
            event_count=("event_id", "size"),
            flagged_events=("provider_suspicious", "sum"),
        )
        .reset_index()
    )


def select_actors(
    summary: pd.DataFrame,
    *,
    min_events: int,
    target_events: int,
    max_events: int,
    min_actor_events: int,
    max_actor_events: int,
    seed: int,
) -> list[str]:
    eligible = summary[
        summary["event_count"].between(min_actor_events, max_actor_events)
    ].copy()

    if eligible.empty:
        raise ValueError("No eligible actors found")
    if eligible["event_count"].sum() < min_events:
        raise ValueError("Eligible actors do not contain enough events")

    rng = np.random.default_rng(seed)
    selected: list[str] = []
    selected_set: set[str] = set()
    total = 0

    def add_row(row: pd.Series) -> bool:
        nonlocal total
        actor = row["actor_pseudo_id"]
        n = int(row["event_count"])
        if actor in selected_set or total + n > max_events:
            return False
        selected.append(actor)
        selected_set.add(actor)
        total += n
        return True

    # Ensure both provider_suspicious classes are represented when possible.
    flagged_pool = eligible[eligible["flagged_events"] > 0]
    unflagged_pool = eligible[eligible["flagged_events"] == 0]
    for pool in (flagged_pool, unflagged_pool):
        if not pool.empty:
            idx = rng.choice(pool.index.to_numpy())
            add_row(pool.loc[idx])

    # Randomized but reproducible actor order.
    candidates = eligible.loc[rng.permutation(eligible.index.to_numpy())]

    # Approach target size.
    for _, row in candidates.iterrows():
        if total >= target_events:
            break
        add_row(row)

    # Guarantee minimum size.
    if total < min_events:
        for _, row in candidates.iterrows():
            if total >= min_events:
                break
            add_row(row)

    if total < min_events:
        raise RuntimeError(
            f"Could not reach {min_events} events without exceeding {max_events}."
        )

    return selected


def build_sample(df: pd.DataFrame, selected_actors: list[str]) -> pd.DataFrame:
    # Exact subset: features are NOT recalculated.
    sample = df[df["actor_pseudo_id"].isin(selected_actors)].copy()
    return sample.sort_values(
        ["actor_pseudo_id", "prior_event_count", "event_id"],
        kind="mergesort",
    ).reset_index(drop=True)


def validate_sample(
    source: pd.DataFrame,
    sample: pd.DataFrame,
    *,
    min_events: int,
    max_events: int,
) -> None:
    assert min_events <= len(sample) <= max_events
    assert list(sample.columns) == list(source.columns)
    assert sample["event_id"].is_unique
    assert "history_available" not in sample.columns

    source_counts = source["actor_pseudo_id"].value_counts()
    sample_counts = sample["actor_pseudo_id"].value_counts()

    # Every selected actor must be complete relative to the public source.
    for actor, count in sample_counts.items():
        assert count == source_counts.loc[actor], f"Incomplete actor: {actor}"

    assert set(sample["event_id"]).issubset(set(source["event_id"]))


def main() -> None:
    args = parse_args()
    validate_args(args)

    df = load_public_csv(args.input)
    summary = summarize_actors(df)

    selected_actors = select_actors(
        summary,
        min_events=args.min_events,
        target_events=args.target_events,
        max_events=args.max_events,
        min_actor_events=args.min_actor_events,
        max_actor_events=args.max_actor_events,
        seed=args.seed,
    )

    sample = build_sample(df, selected_actors)
    validate_sample(
        df,
        sample,
        min_events=args.min_events,
        max_events=args.max_events,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    sample.to_csv(args.output, index=False)

    flagged = int(sample["provider_suspicious"].sum())
    actors = int(sample["actor_pseudo_id"].nunique())

    print("=" * 72)
    print("HEIAuthRisk demo sample created")
    print(f"Source events:       {len(df):,}")
    print(f"Sample events:       {len(sample):,}")
    print(f"Selected actors:     {actors:,}")
    print(f"Public attributes:   {len(sample.columns)}")
    print(f"Flagged events:      {flagged:,}")
    print(f"Flagged proportion:  {flagged / len(sample) * 100:.2f}%")
    print(f"Random seed:         {args.seed}")
    print(f"Output:              {args.output}")
    print("=" * 72)
    print(
        "NOTE: This sample is intended for inspection, tutorials and quick tests; "
        "it is not a statistically representative substitute for the full release."
    )


if __name__ == "__main__":
    main()
