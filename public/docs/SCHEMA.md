# Technical Schema — HEIAuthRisk (42/50)

Scientific file format: UTF-8 CSV, `,` separator, header on the first line.

## Public schema — 42 columns

| # | Column | Expected type | Nullable? |
|---:|---|---|---|
| 1 | `event_id` | string | no |
| 2 | `actor_pseudo_id` | string | no |
| 3 | `event_time_hour_utc` | UTC datetime (hour) | no |
| 4 | `event_hour` | int 0–23 | no |
| 5 | `day_of_week` | int 0–6 | no |
| 6 | `month` | int 1–12 | no |
| 7 | `is_weekend` | int {0,1} | no |
| 8 | `prior_event_count` | int ≥0 | no |
| 9 | `hours_since_last_login` | float ≥0 | yes |
| 10 | `hours_since_first_observed_login` | float ≥0 | no |
| 11 | `logins_24h` | int ≥1 | no |
| 12 | `logins_7d` | int ≥1 | no |
| 13 | `logins_30d` | int ≥1 | no |
| 14 | `login_rate_30d` | float >0 | no |
| 15 | `active_days_30d` | int 1–30 | no |
| 16 | `actor_network_id` | string | no |
| 17 | `ip_version` | int {4,6} | yes |
| 18 | `is_new_ip` | int {0,1} | no |
| 19 | `ip_changed` | int {0,1} | no |
| 20 | `distinct_networks_24h` | int ≥0 | no |
| 21 | `distinct_networks_7d` | int ≥0 | no |
| 22 | `distinct_networks_30d` | int ≥0 | no |
| 23 | `networks_seen_to_date` | int ≥0 | no |
| 24 | `ip_country` | string | yes |
| 25 | `continent` | string | yes |
| 26 | `is_new_country` | int {0,1} | yes |
| 27 | `country_changed` | int {0,1} | yes |
| 28 | `is_new_continent` | int {0,1} | yes |
| 29 | `continent_changed` | int {0,1} | yes |
| 30 | `distinct_countries_24h` | int ≥0 | no |
| 31 | `distinct_countries_7d` | int ≥0 | no |
| 32 | `distinct_countries_30d` | int ≥0 | no |
| 33 | `distinct_countries_to_date` | int ≥0 | no |
| 34 | `login_type` | string | no |
| 35 | `login_challenge_method` | string | yes |
| 36 | `is_new_login_type` | int {0,1} | no |
| 37 | `login_type_changed` | int {0,1} | no |
| 38 | `is_new_challenge` | int {0,1} | yes |
| 39 | `challenge_changed` | int {0,1} | yes |
| 40 | `distinct_login_types_30d` | int ≥0 | no |
| 41 | `distinct_challenges_30d` | int ≥0 | no |
| 42 | `provider_suspicious` | int {0,1} | no |

## Restricted schema — 50 columns

The restricted schema contains the 42 public columns and adds:

| # | Column | Expected type | Nullable? |
|---:|---|---|---|
| 43 | `event_time` | exact UTC datetime | no |
| 44 | `institution_pseudo_id` | string | no |
| 45 | `network_pseudo_id` | string | no in the observed release |
| 46 | `ip_city` | string | yes |
| 47 | `latitude` | float [-90,90] | yes |
| 48 | `longitude` | float [-180,180] | yes |
| 49 | `travel_distance_km` | float ≥0 | yes |
| 50 | `travel_speed_kmh` | float ≥0 | yes |

## Main invariants

- `event_id` is unique and aligns the two schemas.
- `provider_suspicious` is strictly binary and has no missing values.
- `history_available` does not belong to either scientific schema.
- `distinct_networks_24h <= distinct_networks_7d <= distinct_networks_30d <= networks_seen_to_date`.
- `distinct_countries_24h <= distinct_countries_7d <= distinct_countries_30d <= distinct_countries_to_date`.
- `logins_24h <= logins_7d <= logins_30d`.
- `actor_network_id` is not comparable across actors.
- `latitude` and `longitude` are treated as a pair.
- `travel_speed_kmh=0` is valid when the distance is zero and the time interval is positive.
