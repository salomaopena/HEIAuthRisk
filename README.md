# HEIAuthRisk: Successful Cloud Identity Authentication Events for Behavioral and Security Analysis

**HEIAuthRisk** is a pseudonymized dataset of successful authentications in cloud identity environments, built from real records from two higher education institutions.

Release v1.0 contains **73,527 successful authentication events**, associated with **12,190 pseudonymized actors**, observed between **December 19, 2025, and August 12, 2026**. The dataset combines temporal, historical, network, geographic, and authentication attributes with the operational `provider_suspicious` signal provided by the identity provider.

> **Important:** `provider_suspicious=1` only means that the event was flagged by the provider. The field does not constitute *ground truth* of an attack, compromise, or confirmed malicious activity.

The release has two access levels:

- **Public schema:** 42 attributes.
- **Restricted schema:** 50 attributes, corresponding to the 42 public attributes plus 8 additional attributes with greater granularity.

The public dataset was designed for open research, behavioral analysis, identity security studies, UEBA, risk-based authentication, and the development of independent anomaly detection methods.

---

## `README.md` Structure

This document provides the information needed to understand, install, validate, and reuse the public release of HEIAuthRisk v1.0.

The structure includes:

1. basic environment information;
2. dependencies;
3. security and privacy concerns;
4. repository organization;
5. installation;
6. minimum test;
7. reproduction of the analyses from Article 1;
8. supplementary documentation;
9. citation and licensing.

---

## Related Documentation

The documents below are part of the release specification and audit.

| Document | Purpose | Link |
|---|---|---|
| **Data Dictionary** | Operational definition of the 42 public attributes and 8 additional restricted attributes | [Open Data Dictionary](public/docs/DATA_DICTIONARY.md) |
| **Schema** | Formal structure of the public and restricted schemas | [Open Schema](public/docs/SCHEMA.md) |
| **Data Audit Report** | Results of the integrity, consistency, and quality audit | [Open Audit Report](public/docs/DATA_AUDIT_REPORT.md) |
| **Privacy and Pseudonymization Report** | Pseudonymization strategy, minimization, and privacy limitations | [Open Privacy Report](public/docs/PRIVACY_PSEUDONYMIZATION.md) |
| **Installation and Replication Guide** | Detailed installation and methodological replication instructions | [Open guide](public/docs/INSTALLATION_AND_REPLICATION.md) |
| **Dataset Manifest** | Machine-readable metadata, schema, hashes, and release information | [Open manifest](public/data/dataset_manifest_v1.json) |
| **Public Results Notebook** | Reproduction of the descriptive analyses from Article 1 using only public data | [Open notebook](public/notebooks/article_one_results_analysis.ipynb) |

---

## Badges Considered

When applicable to scientific artifact evaluation processes, this release was organized to support criteria for:

- **Availability:** accessible public data, documentation, and code;
- **Functionality:** executable scripts and notebooks;
- **Sustainability:** versioned structure, manifest, schema, and documentation;
- **Reproducibility:** public analyses reproducible from the available dataset.

*The formal awarding of any badge depends on the evaluation process of the corresponding conference or journal.*

---

## Basic Information

The public artifact consists primarily of tabular data in `.csv` format, Markdown documentation, Python scripts, and Jupyter notebooks.

- **Operating system:** Linux, macOS, or Windows.
- **Python:** 3.10 or higher.
- **GPU:** not required for the descriptive analyses in Article 1.
- **Recommended memory:** 2 GB of free RAM or more.
- **Disk space:** at least 500 MB for the dataset, environment, and derived results.
- **Network access:** required only to install dependencies and obtain repository files.

---

## Dependencies

The public analyses from Article 1 primarily use:

| Dependency | Recommended version | Purpose |
|---|---:|---|
| Python | 3.10+ | Execution language |
| pandas | 2.0+ | Tabular data manipulation |
| numpy | 1.24+ | Numerical operations |
| matplotlib | 3.7+ | Figures and visualizations |
| jupyter | current version | Notebook execution |
| python-dotenv | current version | Local pipeline configuration, when applicable |

The exact versions tested by the authors are recorded in:

[**`requirements.txt`**](requirements.txt)

---

## Security and Privacy

[**Privacy and Pseudonymization Report**](public/docs/PRIVACY_PSEUDONYMIZATION.md)

---

## Two-Repository Structure

The recommended organization separates public material from internal and restricted artifacts.

```text
HEIAuthRisk-public/                         (PUBLIC)
├── README.md
├── LICENSE-DATASET.txt
├── LICENSE-CODE.txt
├── CITATION.cff
├── codemeta.json
├── .zenodo.json
├── requirements.txt
│
├── data/
│   ├── suspicious_logins_public_v1.csv
│   └── dataset_manifest_v1.json
│
├── notebooks/
│   └── article_one_results_analysis.ipynb
│
├── src/
│   └── processed.py
│   └── extract_suspicious_logins.py
│   └── validate_release.py
│   └── validate_security_dataset.py
│   └── functions.py
│   └── benchmark_ml.py
│
└── docs/
    ├── DATA_DICTIONARY.md
    ├── SCHEMA.md
    ├── DATA_AUDIT_REPORT.md
    ├── PRIVACY_PSEUDONYMIZATION.md
    └── INSTALLATION_AND_REPLICATION.md
```

```text
HEIAuthRisk-restricted/                 (RESTRICTED / INTERNAL)
├── .env
├── .gitignore
├── credentials.json
│
├── data/
│   ├── raw/
│   │   ├── institution_a/
│   │   └── institution_b/
│   └── processed/
│       └── suspicious_logins_restricted_v1.csv
│
├── notebooks/
│   └── article_one_statistics_release_gate.ipynb
│
├── src/
│   ├── processed.py
│   ├── extract_suspicious_logins.py
│   └── functions.py
│
└── internal/
    └── audit_and_provenance_artifacts/
```

---

## Release Schema

### Public Schema

The file:

```text
data/suspicious_logins_public_v1.csv
```

contains:

- **73,527 events**;
- **42 attributes**;
- **12,190 pseudonymized actors**.

The public attributes are organized into six blocks:

1. identification and temporal;
2. activity and history;
3. network/IP;
4. geography;
5. authentication;
6. provider signal.

The complete specification is available in:

[**Data Dictionary**](public/docs/DATA_DICTIONARY.md)

and:

[**Schema**](public/docs/SCHEMA.md)

### Restricted Schema

The restricted schema contains the same 42 public attributes and adds:

```text
event_time
institution_pseudo_id
network_pseudo_id
ip_city
latitude
longitude
travel_distance_km
travel_speed_kmh
```

for a total of **50 attributes**.

The restricted file is not included in the public distribution.

---

## Sample

suspicious_logins_demo_sample.csv is a small subset intended for inspection, tutorials, and quick software tests. Actors are sampled rather than individual rows so that the observed event sequence of each selected actor is preserved. The sample must not be treated as representative of the full dataset and should not be used to reproduce the descriptive statistics reported in the article.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/salomaopena/HEIAuthRiskDataset.git

cd HEIAuthRisk-dataset

# 2. Create a virtual environment
python3 -m venv venv

# Linux/macOS
source venv/bin/activate

# Windows
# venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

After installation, the public dataset and the Article 1 notebook can be used without access to the restricted dataset.

---

## Minimum Test

The test below checks whether the public dataset has the expected size and schema.

```bash
python3 -c "
import pandas as pd

df = pd.read_csv('data/suspicious_logins_public_v1.csv')

assert len(df) == 73526, f'Unexpected number of events: {len(df)}'
assert len(df.columns) == 42, f'Unexpected number of attributes: {len(df.columns)}'
assert df['event_id'].is_unique, 'event_id must be unique'
assert set(df['provider_suspicious'].dropna().astype(int).unique()) == {0, 1}
assert 'history_available' not in df.columns

print(
    'Minimum test passed:',
    len(df),
    'events,',
    len(df.columns),
    'public attributes'
)
"
```

**Expected result:**...

```text
Minimum test passed: 73526 events, 42 public attributes
```

---

## Reproducing the Analyses from Article 1

The public notebook:

[**`article_one_results_analysis.ipynb`**](public/notebooks/article_one_results_analysis.ipynb)

uses only:

```text
data/suspicious_logins_public_v1.csv
```

and reproduces the descriptive analyses compatible with the public release.

### Analysis #1 — Dataset Overview

Reproduces:

- number of events;
- number of actors;
- public temporal coverage;
- number and proportion of events flagged by the provider.

Reference values:

```text
Events:                 73,527
Pseudonymized actors:   12,190
provider_suspicious = 1: 7,196
provider_suspicious = 0: 66,330
```

### Analysis #2 — Activity and Observed History

Reproduces:

- events per actor;
- actors with a single event;
- actors with recurring events;
- events with prior history;
- Gini coefficient;
- share of the most active 1% and 10%.

History availability is derived using:

```python
prior_event_count > 0
```

### Analysis #3 — Authentication Characteristics

Reproduces distributions of:

```text
login_type
login_challenge_method
provider_suspicious
```

and enables the analysis of derived attributes such as novelty, change, and recent diversity of authentication methods.

### Analysis #4 — Geographic Characteristics

Reproduces:

- distribution by country;
- distribution by continent;
- recent country diversity;
- geographic changes and novelty.

The public release preserves normalized country values. Rare categories are not replaced with `Other` in the CSV.

### Analysis #5 — Network Characteristics

The identifier:

```text
actor_network_id
```

enables analysis, within the same actor, of:

- first network occurrence;
- network change;
- number of distinct networks within 24 hours, 7 days, and 30 days;
- cumulative number of observed networks.

This identifier is not comparable across actors.

### Analysis #6 — Missingness

The notebook generates a missing-value report for the 42 public attributes.

Some missing values are structural. For example:

```text
hours_since_last_login = NA
```

for each actor's first observed event.

The specific rules for each attribute are provided in the:

[**Data Dictionary**](public/docs/DATA_DICTIONARY.md)

---

## Internal Release Validation

Full validation uses the restricted notebook:

```text
article1_statistics_release_gate.ipynb
```

This notebook **is not included in the public repository** because it depends on the restricted dataset.

The release gate checks, among other aspects:

- exact 42/50 schema;
- SHA-256 hashes;
- public/restricted alignment by `event_id`;
- uniqueness;
- domains;
- absence of prohibited attributes;
- independent reconstruction of temporal features;
- network features;
- geographic features;
- authentication features;
- mobility;
- missingness;
- temporal invariants;
- institutional statistics.

The release should only be considered validated when the notebook finishes with:

```text
RELEASE VALIDATION: PASS
```

The exported validation report can be consulted at:

[**Final Release Validation Report**](public/data/dataset_manifest_v1.json)

---

## Reproducibility

The documentation distinguishes four levels of reproducibility:

### Public Analytical Reproducibility

Execution of the analyses directly on the 42 available attributes.

### Reconstruction of Public Attributes

Some derived attributes can be reconstructed from the public columns themselves, including various temporal, network, geographic, and authentication indicators.

### Methodological Replication

Another institution with legitimate access to its own records can reuse the extraction and processing code to produce a structurally comparable resource.

### Full Reconstruction

The exact reconstruction of the 73,527 original events is not public because it depends on the original institutional logs and private pseudonymization keys.

More details:

[**Installation and Replication Guide**](public/docs/INSTALLATION_AND_REPLICATION.md)

---

## Integrity and Audit

The release is accompanied by a machine-readable manifest containing information such as:

- dataset version;
- schema version;
- number of events;
- number of actors;
- coverage period;
- column names and order;
- SHA-256 hashes;
- pseudonymization rules;
- validation information.

See:

[**Dataset Manifest**](public/data/dataset_manifest_v1.json)

and:

[**Data Audit Report**](public/docs/DATA_AUDIT_REPORT.md)

---

## Data Availability

### Public Release

**Repository:**

[*https://github.com/salomaopena/HEIAuthRiskDataset*](https://github.com/salomaopena/HEIAuthRiskDataset)

**DOI / Zenodo:**

[<INSERT_DOI_OR_ZENODO_URL>](https://...)

### Restricted Data

The restricted schema is not made available as an open file.

Justified requests may be considered following an assessment of the scientific purpose, privacy risks, and applicable institutional requirements. Where appropriate, access may be limited to the minimum subset of attributes necessary for the proposed research.

---

## Citation

See:

[**`CITATION.cff`**](CITATION.cff)

```text
Pena, S. B. N.; Quincozes, S. E.; Miani, R. S.
HEIAuthRisk: A Dataset of Successful Cloud Identity Authentication Events
for Behavioral and Security Analysis.
Dataset version 2.0.
2026. <DOI/URL>.
```

---

## License

- **Dataset:** [LICENSE-DATASET.txt](LICENSE-DATASET.txt)
- **Code:** [LICENSE-CODE.txt](LICENSE.txt)

---

## Contact

**Corresponding author:**  
Salomão Bento Nilo Pena

**Institution / group:**  
<INSERT_AFFILIATION>

**Institutional email:**  
<INSERT_EMAIL>

**Project page:**  
<INSERT_PROJECT_URL>
