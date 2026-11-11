# Data Dictionary — HEIAuthRisk

## Consolidated Scientific Schema (42 Public / 50 Restricted)

- **Public Schema:** 42 observed and deterministically derived attributes.
- **Restricted Schema:** 50 attributes (**Superset**: 42 public + 8 controlled-access attributes with high temporal and geographic precision).
- **Core Semantic Principle:** Behavioral attributes describe the actor's temporal sequence and history. The `provider_suspicious` attribute is preserved in strict isolation as an operational provider signal (it does not constitute an attack or compromise label).

---

## 1. Public Schema — 42 Attributes

### Global Derivation Conventions

- The canonical ordering per actor is `actor_pseudo_id` → exact `event_time` in ascending order → `event_id` in ascending order as a deterministic tie-breaker.
- Tie-breaking by `event_id` ensures computational reproducibility but does not prove the actual physical order of simultaneous events.
- No behavioral attribute uses future events.
- Windows indicated by `t_h` use `event_time_hour_utc`, with the lower bound and current event included.
- Missing values do not form artificial categories in diversity counts.
- `0` represents a valid value; `NA` represents missingness or inability to calculate, where applicable.
- `actor_network_id` is stable only within the same actor and is not comparable across actors.

### 1.1 Identification and Block A — Temporal (7 Attributes)

All temporal attributes are referenced exclusively in **UTC**.

| # | Attribute | Type | Source / Dependency | Operational Definition | *Missing* Rule |
|---:|---|---|---|---|---|
| 1 | `event_id` | Text | Derived | Deterministic and unique event identifier (HMAC). Used for uniqueness and ordering tie-breaking. | Not allowed |
| 2 | `actor_pseudo_id` | Text | Pseudonymization | Stable actor pseudonym within the institutional scope. | Not allowed |
| 3 | `event_time_hour_utc` | UTC Datetime | Transformed (`event_time`) | Exact timestamp truncated to the beginning of the UTC hour (e.g., `19:32:10` → `19:00:00`). | Not allowed |
| 4 | `event_hour` | Integer `0–23` | Derived (`event_time_hour_utc`) | Hour of the day in UTC. | Not allowed |
| 5 | `day_of_week` | Integer `0–6` | Derived (`event_time_hour_utc`) | UTC day of the week (0 = Monday, ..., 6 = Sunday). | Not allowed |
| 6 | `month` | Integer `1–12` | Derived (`event_time_hour_utc`) | Calendar month in UTC. | Not allowed |
| 7 | `is_weekend` | Binary `0/1` | Derived (`day_of_week`) | `1` if `day_of_week` ∈ {5, 6}; `0` otherwise. | Not allowed |

---

### 1.2 Block B — Activity and History (8 Attributes)

Calculated strictly in the actor's temporal order.

| # | Attribute | Type | Temporal Basis | Operational Definition | Actor's 1st Event |
|---:|---|---|---|---|---|
| 8 | `prior_event_count` | Integer ≥ 0 | Cumulative history | Number of previous events observed for the same actor. | `0` |
| 9 | `hours_since_last_login` | Decimal ≥ 0 | Exact timestamp | Interval in hours since the immediately preceding login: `(t_i - t_{i-1}) / 3600`. | `NA` |
| 10 | `hours_since_first_observed_login` | Decimal ≥ 0 | Exact timestamp | Time in hours since the actor's first observed event in the collection: `(t_i - t_first) / 3600`. | `0.0` |
| 11 | `logins_24h` | Integer ≥ 1 | Window `[t-24h, t]` | Total actor logins in the last 24 hours (includes the current event). | `1` |
| 12 | `logins_7d` | Integer ≥ 1 | Window `[t-7d, t]` | Total actor logins in the last 7 days. | `1` |
| 13 | `logins_30d` | Integer ≥ 1 | Window `[t-30d, t]` | Total actor logins in the last 30 days. | `1` |
| 14 | `login_rate_30d` | Decimal > 0 | Exposure window | Average daily login rate: `logins_30d / observed_calendar_days_30d`, where `observed_calendar_days_30d = min(30, (current_UTC_date - first_event_UTC_date).days + 1)`. | `1.0` |
| 15 | `active_days_30d` | Integer `1–30` | 30 UTC Days | Number of distinct UTC dates with at least one login in the last 30 days. | `1` |

### Block B Invariants

- `logins_24h <= logins_7d <= logins_30d`
- `1 <= active_days_30d <= 30`
- `active_days_30d <= logins_30d`
- `hours_since_last_login = NA` at the first event
- `hours_since_first_observed_login = 0.0` at the first event

---

### 1.3 Block C — Network / IP (8 Attributes)

| # | Attribute | Type | Temporal Basis | Operational Definition | *Missing* / 1st Event |
|---:|---|---|---|---|---|
| 16 | `actor_network_id` | Text | Current event | **Actor-scoped** pseudonymized network/IP identifier. Not comparable across actors. | `NA` if IP is missing |
| 17 | `ip_version` | Integer `{4,6}` | Current event | Observed IP protocol version (4 or 6). | `NA` if unavailable |
| 18 | `is_new_ip` | Binary `0/1/NA` | Prior history | `1` if the network has never appeared in the actor's history; `0` if it has appeared before. | `1` (if IP is valid); `NA` if IP is missing |
| 19 | `ip_changed` | Binary `0/1/NA` | Previous event | `1` if the network differs from the previous event's network; `0` if identical or at the 1st event. | `0` (1st event); `NA` if the comparison involves a null value |
| 20 | `distinct_networks_24h` | Integer ≥ 0 | Window `[t_h-24h, t_h]` | Number of distinct known networks (`actor_network_id`) in the window; missing values are excluded from the count. | `0` only if no known network exists in the window; ≥ 1 if the current network is known |
| 21 | `distinct_networks_7d` | Integer ≥ 0 | Window `[t_h-7d, t_h]` | Number of distinct known networks observed in the last 7 days; missing values are excluded from the count. | `0` only if no known network exists in the window |
| 22 | `distinct_networks_30d` | Integer ≥ 0 | Window `[t_h-30d, t_h]` | Number of distinct known networks observed in the last 30 days; missing values are excluded from the count. | `0` only if no known network exists in the window |
| 23 | `networks_seen_to_date` | Integer ≥ 0 | Cumulative history | Cumulative total of distinct known networks observed up to the current event. An event with a missing network neither increments nor resets the cumulative count. | `0` while no known network has been observed; otherwise preserves the cumulative count |

### Block C Invariants

- `distinct_networks_24h <= distinct_networks_7d <= distinct_networks_30d <= networks_seen_to_date`
- If the current `actor_network_id` is known, all three window counts must be at least `1`.
- `is_new_ip = 1` implies the addition of a new network to the actor's cumulative history.
- Network windows use `event_time_hour_utc`, allowing recomputation from the public schema.

---

### 1.4 Block D — Geography (10 Attributes)

| # | Attribute | Type | Temporal Basis | Operational Definition | *Missing* / 1st Event |
|---:|---|---|---|---|---|
| 24 | `ip_country` | Text | Current event | Normalized code/name of the country associated with the source IP. | `NA` if unavailable |
| 25 | `continent` | Text | Current event | Continent deterministically mapped from `ip_country`. | `NA` if country is missing |
| 26 | `is_new_country` | Binary `0/1/NA` | Prior history | `1` if the country has never previously appeared in the actor's history. | `1` (if country is valid); `NA` if missing |
| 27 | `country_changed` | Binary `0/1/NA` | Previous event | `1` if the country differs from the one associated with the immediately preceding event. | `0` (1st event); `NA` if missing |
| 28 | `is_new_continent` | Binary `0/1/NA` | Prior history | `1` if the continent has never appeared in the actor's history. | `1` (if continent is valid); `NA` if missing |
| 29 | `continent_changed` | Binary `0/1/NA` | Previous event | `1` if the continent differs from that of the immediately preceding event. | `0` (1st event); `NA` if missing |
| 30 | `distinct_countries_24h` | Integer ≥ 0 | Window `[t_h-24h, t_h]` | Distinct known countries observed in the window; missing countries are excluded from the count. | `0` only if no known country exists in the window; ≥ 1 if the current country is known |
| 31 | `distinct_countries_7d` | Integer ≥ 0 | Window `[t_h-7d, t_h]` | Distinct known countries observed in the last 7 days; missing countries are excluded from the count. | `0` only if no known country exists in the window |
| 32 | `distinct_countries_30d` | Integer ≥ 0 | Window `[t_h-30d, t_h]` | Distinct known countries observed in the last 30 days; missing countries are excluded from the count. | `0` only if no known country exists in the window |
| 33 | `distinct_countries_to_date` | Integer ≥ 0 | Cumulative history | Cumulative total of distinct known countries observed up to the current event. An event with a missing country neither increments nor resets the cumulative count. | `0` while no known country has been observed; otherwise preserves the cumulative count |

### Block D Invariants

- `distinct_countries_24h <= distinct_countries_7d <= distinct_countries_30d <= distinct_countries_to_date`
- If `ip_country` is known, `continent` must be known.
- `is_new_country = 1` implies the addition of a new country to the actor's cumulative history.

---

### 1.5 Block E — Authentication (8 Attributes)

| # | Attribute | Type | Temporal Basis | Operational Definition | *Missing* / 1st Event |
|---:|---|---|---|---|---|
| 34 | `login_type` | Categorical | Current event | Login type reported by the provider (e.g., `google_password`, `reauth`). | `NA` if unavailable |
| 35 | `login_challenge_method` | Text | Current event | Authentication challenge method(s) or category/categories recorded by the provider, normalized and separated by `\|` (e.g., `password\|security_key`). | `none` is a valid category; `NA` if missing |
| 36 | `is_new_login_type` | Binary `0/1/NA` | Prior history | `1` if the current `login_type` has never appeared in the actor's history. | `1` (if type is valid); `NA` if missing |
| 37 | `login_type_changed` | Binary `0/1/NA` | Previous event | `1` if `login_type` differs from that of the immediately preceding event. | `0` (1st event); `NA` if missing |
| 38 | `is_new_challenge` | Binary `0/1/NA` | Prior history | `1` if at least one category of the current challenge has never appeared in the actor's history. | `1` (1st valid set); `NA` if missing |
| 39 | `challenge_changed` | Binary `0/1/NA` | Previous event | `1` if the challenge set differs from the previous event (regardless of order). | `0` (1st event); `NA` if missing |
| 40 | `distinct_login_types_30d` | Integer ≥ 0 | Window `[t_h-30d, t_h]` | Distinct known login types observed in the 30-day window; missing values are excluded from the count. | `0` only if no known type exists in the window; ≥ 1 if the current type is known |
| 41 | `distinct_challenges_30d` | Integer ≥ 0 | Window `[t_h-30d, t_h]` | Distinct individual challenge categories observed in the 30-day window; missing values are excluded from the count, and `none` is a valid category. | `0` only if no known category exists in the window; ≥ 1 if the current challenge is known |

---

### 1.6 Block F — Provider Signal (1 Attribute)

| # | Attribute | Type | Source | Operational Definition | *Missing* Rule |
|---:|---|---|---|---|---|
| 42 | `provider_suspicious` | Binary `0/1` | Identity Provider | `1` = successful authentication event flagged as suspicious by the provider; `0` = not flagged. `1` does not represent a confirmed attack/compromise, and `0` does not represent confirmed legitimacy. | **Not allowed**. Halts pipeline execution if null. |

### Signal Semantic Rule

- `provider_suspicious = 1` only means that the provider flagged the event.
- `provider_suspicious = 1` does not imply a confirmed attack or compromise.
- `provider_suspicious = 0` does not imply confirmed legitimacy.
- The signal is not used as an input to generate core behavioral attributes.

---

## 2. Additional Restricted Schema Attributes (+8 Attributes)

The Restricted Schema contains the **42 public attributes** and adds exactly these **8 controlled-access fields**:

| # | Attribute | Type | Source | Scientific and Operational Purpose | *Missing* Rule |
|---:|---|---|---|---|---|
| 43 | `event_time` | Exact UTC Datetime | Normalized source | Original temporal precision, canonical ordering, and auditing. | Required |
| 44 | `institution_pseudo_id` | Text | Pseudonymization | Source institution identifier (controlled inter-institutional comparison). | Required |
| 45 | `network_pseudo_id` | Text | Pseudonymization | Stable network identifier within the institutional scope (recognizes the same network across actors). | `NA` if source IP is missing |
| 46 | `ip_city` | Text | IP Geolocation | Fine-grained geographic analyses (estimated city). | `NA` if unavailable |
| 47 | `latitude` | Decimal `[-90, 90]` | IP Geolocation | Coordinate for geodesic mobility calculation. | Must form a pair with `longitude` |
| 48 | `longitude` | Decimal `[-180, 180]` | IP Geolocation | Coordinate for geodesic mobility calculation. | Must form a pair with `latitude` |
| 49 | `travel_distance_km` | Decimal ≥ 0 / `NA` | Derived (`Haversine`) | Distance in km between the current event and the immediately preceding event from the same actor. | `NA` if it is the 1st event or coordinates are missing |
| 50 | `travel_speed_kmh` | Decimal ≥ 0 / `NA` | Derived | Apparent speed: `travel_distance_km / hours_since_last_login`. | `NA` if `travel_distance_km` is missing or `hours_since_last_login <= 0`; a distance of `0` with a positive interval produces a speed of `0` |

---

## 3. Availability Summary

| Access Layer | Number of Attributes | Main Purpose |
| :--- | :---: | :--- |
| **Public Schema** | **42 attributes** | Open research, analytical reproducibility, and open benchmarks. |
| **Restricted Schema** | **50 attributes** (Superset) | Controlled research, exact temporal auditing, and detailed geographic studies. |
| **Internal Artifacts** | Outside the schema | Traceability, security, and encryption keys. |
