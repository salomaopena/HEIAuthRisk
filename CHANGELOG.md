# Changelog

All notable changes to HEIAuthRisk are documented in this file.
The project follows [Semantic Versioning](https://semver.org/).

## 1.0.0 — 2026-11

Initial public release.

- Pseudonymized dataset of 73,527 successful Google Workspace authentication events associated with 12,190 actor pseudonyms from two higher-education institutions.
- Public schema with 42 attributes covering authentication context, observed history, recent login frequency, and network and geographic novelty.
- Provider-generated `provider_suspicious` operational signal (not forensic ground truth of account compromise).
- Institution-specific HMAC pseudonymization applied in the processing stage.
- Public timestamps generalized to hour-level UTC and rare countries grouped as `Other`.
- Manifest, checksums, and integrity checks.
- Validation code, data dictionary, and privacy/provenance documentation.
- Public characterization notebook for the descriptive statistics of Article 1.
- Restricted tier, raw institutional logs, credentials, and HMAC keys are not part of the public release.
