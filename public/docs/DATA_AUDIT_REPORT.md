# Quality and Audit Report — HEIAuthRisk (42/50)

## 1. Scope

The release contains **73,526 events**, **12,190 pseudonymized actors**, **2 institutions**, 42 public attributes, and 50 restricted attributes. The exact observed period is from **2025-12-19 19:56:08.276 UTC** to **2026-08-12 16:14:21.545 UTC**.

Version 42/50 was regenerated from the previously validated consolidated internal dataset of 73,526 events, preserving the same `event_id`, `actor_pseudo_id`, `institution_pseudo_id`, and `network_pseudo_id`. The purpose of this step was to change the scientific schema and recalculate the derived features without reintroducing rows already removed during the previous cleaning of the 19 raw files.

## 2. Core Statistics

- actors with a single event: **347 (2.85%)**;
- recurring actors: **11,843 (97.15%)**;
- events with prior history (`prior_event_count>0`): **61,336 (83.42%)**;
- first observed events: **12,190 (16.58%)**;
- Q1/median/Q3 of events per actor: **3 / 3 / 4**;
- maximum per actor: **1,847**;
- activity Gini: **0.537553**;
- top 1% of actors: **29.93%** of events;
- top 10%: **52.99%**.

## 3. Provider Signal

- `provider_suspicious=0`: **66,330**;
- `provider_suspicious=1`: **7,196**;
- flagged proportion: **9.7870%**.

This proportion describes operational flagging by the provider, not the prevalence of confirmed attacks.

## 4. Authentication and Geography

`login_type`: `google_password` 35,454; `reauth` 27,277; `exchange` 10,795.

The dataset contains **23 distinct known countries** and one row with a missing country. The largest volumes are Angola (47,314) and Brazil (25,281). `continent` is derived deterministically from `ip_country`, avoiding inconsistencies in the old legacy geographic field.

## 5. Actor-Scoped Public Network

`actor_network_id` has **37,684 distinct values** in the public release. The identifier is actor-scoped, and validation confirms that no `actor_network_id` is shared across different actors. The restricted `network_pseudo_id` remains available only for controlled studies that need to recognize the same network across actors.

## 6. Observed Missingness

### Public

- `hours_since_last_login`: **12,190**
- `ip_version`: **2**
- `country_changed`: **2**
- `challenge_changed`: **2**
- `continent_changed`: **2**
- `ip_country`: **1**
- `continent`: **1**
- `is_new_continent`: **1**
- `is_new_country`: **1**
- `login_challenge_method`: **1**
- `is_new_challenge`: **1**

`hours_since_last_login` has 12,190 structurally missing values: one for each actor's first observed event. Missing values in change attributes may also occur in the row immediately following a missing source value, because comparison with the previous event becomes undefined.

### Restricted — Additional Missing Values

- `ip_city`: **1**
- `latitude`: **2,043**
- `longitude`: **2,043**
- `travel_distance_km`: **14,851**
- `travel_speed_kmh`: **16,115**

## 7. Integrity and Hashes

- Public SHA-256: `47be2f74f1c1db3f1dbed2cf4343ca099de9a1ca59373c1b5eff2686688073ec`
- Restricted SHA-256: `dcf78de104b3bf4dad77502193dfd3af406844bc6afc1ea0570ddeb05cf366af`
- public/restricted rows: 73,526 / 73,526;
- public/restricted columns: 42 / 50;
- `event_id`: unique in both files;
- `provider_suspicious` domain: {0,1};
- `history_available`: absent from both scientific schemas;
- login, network, and country window invariants: validated;
- `latitude`/`longitude` pair: aligned missingness.

## 8. Reproducibility

The public release allows recomputation of features based on `event_time_hour_utc`, `actor_network_id`, `ip_country`, `login_type`, and `login_challenge_method`. The exact login windows and intervals in hours were calculated using the restricted `event_time` and are published as derived values.
