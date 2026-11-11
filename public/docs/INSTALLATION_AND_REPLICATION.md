# Installation, Validation, and Methodological Replication

This guide separates two operations: **using the public release** and **replicating the method in another Google Workspace domain**.

## 1. Using the Public Release

Requirements: Python 3.10+.

```bash
git clone https://github.com/salomaopena/HEIAuthRisk.git
cd HEIAuthRisk
python -m venv .venv
source .venv/bin/activate
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python src/validate_public_release.py
```

No Google credentials are required to use or validate the public CSV.

## 2. Institutional Replication

Replication requires legitimate administrative access to the institution's own Google Workspace records, authorized configuration of the Admin SDK Reports API, and private institutional HMAC keys.

Scope used for collection:

```text
https://www.googleapis.com/auth/admin.reports.audit.readonly
```

The extractor selects successful authentication events (`applicationName=login`, `eventName=login_success`).

For multiple institutions, raw files must be separated by institution, and each institution must use a different HMAC key. The keys are not included in the release.

## 3. Processing

`src/processed.py` implements the 42/50 contract. The logical sequence is: cleaning → pseudonymization → canonical ordering → temporal features → activity/history → network → geography → authentication → provider signal → public/restricted schemas → validations.

Methodological replication at another institution will produce a structurally comparable dataset, not the same 73,526 events.

## 4. Public Reproducibility versus Full Reconstruction

The public release supports analyses of all published values and recomputation of features built using only public columns. Full reconstruction of the original data requires institutional logs and private keys, which are not distributed.
