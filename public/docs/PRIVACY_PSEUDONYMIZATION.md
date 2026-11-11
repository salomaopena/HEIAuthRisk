# Privacy, Pseudonymization, and Governance — HEIAuthRisk

## 1. Terminology

HEIAuthRisk is **pseudonymized**. Stable identifiers allow events from the same actor to be linked throughout the observed period. No claim is made that reidentification is impossible.

## 2. Public Identifiers

`actor_pseudo_id` links events from the same actor without publishing the original identifier.

`actor_network_id` is deliberately **actor-scoped**. The same actor using the same network receives the same identifier; the same source address used by different actors does not produce a comparable public identifier. This design preserves the ability to study intra-actor network novelty, change, and diversity without publishing a key for identifying shared networks across users.

`actor_network_id` is not a synthetic IP address and must not be used for geolocation, ASN, reputation, or routing.

## 3. Restricted Information

The restricted schema adds the exact timestamp, pseudonymized institution, `network_pseudo_id`, city, and geographic coordinates, as well as apparent distance and speed between consecutive events.

`network_pseudo_id` is institution-scoped and can identify the same network source across actors, which is why it remains under controlled access.

## 4. Geography

The public dataset preserves `ip_country` and derives `continent` deterministically from the country. Rare countries are not replaced with `Other` in the CSV; grouping may be performed only during analysis.

City and coordinates remain restricted. IP geolocation is an estimate of the network source and not confirmation of a person's physical location.

## 5. Temporality

The public timestamp is generalized to the UTC hour. The exact timestamp remains restricted. Therefore, some features based on seconds/milliseconds are usable in the public dataset but cannot be fully reconstructed from the other public columns.

## 6. Governance

The dataset must be used strictly for academic research, in accordance with the distribution license. Restricted data may be considered for controlled access subject to a justified scientific purpose, privacy assessment, and applicable institutional requirements.
