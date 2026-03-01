# PKI-Based Secure Software Update Approval and Distribution System

**Cybersecurity Capstone Project – Production-Grade Academic Implementation**
---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Threat Model](#2-threat-model)
3. [Security Controls Reference](#3-security-controls-reference)
4. [Directory Structure](#4-directory-structure)
5. [Quick-Start Setup](#5-quick-start-setup)
6. [Step-by-Step Workflow](#6-step-by-step-workflow)
7. [API Reference](#7-api-reference)
8. [Security Design Decisions](#8-security-design-decisions)
9. [Security Assumptions and Known Limitations](#9-security-assumptions-and-known-limitations)
10. [Future Improvements](#10-future-improvements)

---

## 1. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Certificate Authority                          │
│  ca_private.key  ←  kept offline/secret                              │
│  ca_cert.pem     →  distributed to server + all clients (trust anchor)│
└───────────────────────────┬──────────────────────────────────────────┘
                            │ signs
                ┌───────────▼───────────┐
                │  Developer Certificate │
                │  dev_private.key       │  (kept in CI/CD secrets)
                │  dev_cert.pem          │  (submitted with each update)
                └───────────┬───────────┘
                            │
         ┌──────────────────▼────────────────────┐
         │           Update Server (FastAPI)       │
         │                                         │
         │  /submit  → verifies cert chain         │
         │             verifies signature           │
         │             stores in PENDING            │
         │                                         │
         │  /approve → release manager approves    │
         │             rollback protection          │
         │             moves to RELEASED            │
         │             updates signed manifest      │
         │                                         │
         │  /manifest.json  (public)               │
         │  /updates/<ver>/<file>  (public)        │
         └──────────────────┬────────────────────-─┘
                            │ HTTPS (TLS in production)
         ┌──────────────────▼────────────────────┐
         │         Client Application (GUI)        │
         │                                         │
         │  1. Fetch manifest                      │
         │  2. Verify manifest integrity hash      │
         │  3. Compare semantic versions           │
         │  4. Download ZIP                        │
         │  5. Verify SHA-256                      │
         │  6. Fetch company cert                  │
         │  7. Verify cert chain (CA trust anchor) │
         │  8. Verify cert fingerprint             │
         │  9. Verify RSA signature                │
         │  10. Rollback protection check          │
         │  11. Safe ZIP extraction (Zip Slip)     │
         └────────────────────────────────────────┘
```

### Two-Phase Update Distribution

**Phase 1 – Submission** (`/submit`): The developer signs the update package and submits it along with their certificate and signature. The server verifies the certificate chain and signature, then stores the update in `storage/pending/`. It is **not yet visible to clients**.

**Phase 2 – Approval** (`/approve`): A Release Manager (separate role from the developer) calls `/approve` with an admin token. The server performs a rollback check, moves the release to `storage/updates/`, and updates the signed manifest. Only then do clients see the update.

This separation of duties is an **insider-threat mitigation** – a developer cannot ship their own update without Release Manager approval.

---

## 2. Threat Model

| Threat | Mitigation |
|--------|-----------|
| **Supply-chain attack** – attacker generates their own CA and dev cert | CA cert is on server disk; submitter cannot override the trust anchor |
| **MITM on update download** – attacker intercepts the ZIP | SHA-256 hash checked after download; RSA signature verified against pinned CA |
| **Rollback/downgrade attack** – push an old vulnerable version | Server rejects approval if version ≤ current latest; client double-checks |
| **Zip Slip** – malicious ZIP with `../../etc/passwd` paths | Each member resolved and asserted to be inside target directory |
| **Manifest tampering** – attacker modifies JSON in transit | SHA-256 integrity hash embedded in manifest, checked on every read |
| **Expired certificate** – reuse of an old revoked cert | Validity window checked server-side and client-side |
| **Insider threat (developer self-approves)** | Submit and approve are separate endpoints requiring separate credentials |
| **Certificate substitution** – attacker uses a different CA-signed cert | Manifest stores cert fingerprint; client verifies fingerprint matches downloaded cert |
| **Self-signed certificate** – attacker generates their own cert | Issuer must match CA subject; CA's RSA signature verified over TBS bytes |

---

## 3. Security Controls Reference

| Control | Standard | Implementation |
|---------|----------|----------------|
| Software Integrity | NIST SP 800-53 **SI-7** | SHA-256 + RSA signature on every update |
| Access Enforcement | NIST **AC-3** | Submit/approve separation; admin token |
| Audit Events | NIST **AU-2** | `storage/logs/audit.log` – submit, approve, deny |
| Change Management | ISO 27001 **A.8.32** | Approval gate before distribution |
| Input Validation | NIST **SI-10** | Semver regex; sha256 format; filename sanitisation |
| Transmission Security | NIST **SC-8** | HTTPS required in production (plaintext only for lab) |
| Rollback Protection | NIST **SI-7(6)** | Semantic version comparison; both server and client |
| Certificate Validation | RFC 5280 | Full chain; validity window; issuer binding; CA signature |
| Path Traversal Prevention | CWE-22 | `os.path.basename` + `resolve().relative_to()` |

---

## 4. Directory Structure

```
pki-project/
│
├── update-server/
│   ├── main.py                  # FastAPI server (submit, approve, manifest)
│   ├── requirements.txt
│   ├── pki/
│   │   └── ca_cert.pem          # ← copy here from developer-tools/pki/
│   └── storage/
│       ├── manifest.json        # signed release manifest (auto-created)
│       ├── pending/             # awaiting approval
│       │   └── <version>/
│       │       ├── update.zip
│       │       ├── dev_cert.pem
│       │       ├── signature.b64
│       │       └── meta.json
│       ├── updates/             # approved releases (served to clients)
│       │   └── <version>/
│       │       ├── update.zip
│       │       ├── dev_cert.pem
│       │       └── signature.b64
│       └── logs/
│           └── audit.log
│
├── client-app/
│   ├── gui.py                   # Tkinter GUI (entry point)
│   ├── updater.py               # Security-critical core logic
│   ├── ca_cert.pem              # ← copy here from developer-tools/pki/
│   ├── requirements.txt
│   └── client_state.json        # auto-created: tracks installed version
│
└── developer-tools/
    ├── generate_ca.py           # Step 1: create root CA
    ├── generate_dev_cert.py     # Step 2: create developer signing cert
    ├── sign_update.py           # Step 3: sign + submit update
    ├── requirements.txt
    └── pki/
        ├── ca_private.key       # SECRET – never commit to git
        ├── ca_cert.pem          # Public – distribute to server and clients
        ├── dev_private.key      # SECRET – store in CI/CD secrets
        └── dev_cert.pem         # Submitted with each update
```

---

## 5. Quick-Start Setup

### 5.1 Install Python dependencies

```bash
# Update server
cd update-server && pip install -r requirements.txt

# Client
cd client-app && pip install -r requirements.txt
# On Debian/Ubuntu also: sudo apt install python3-tk

# Developer tools
cd developer-tools && pip install -r requirements.txt
```

### 5.2 Generate PKI (one-time)

```bash
cd developer-tools

# Create root CA (10-year self-signed certificate)
python generate_ca.py

# Create developer signing certificate (1-year, signed by CA)
python generate_dev_cert.py --cn "ACME Release Bot" --days 365

# Distribute CA certificate (public – safe to share)
cp pki/ca_cert.pem ../update-server/pki/ca_cert.pem
cp pki/ca_cert.pem ../client-app/ca_cert.pem
```

### 5.3 Start the server

```bash
cd update-server
python main.py
# Server listens on http://0.0.0.0:9000
```

### 5.4 Edit client config

In `client-app/gui.py` set:
```python
SERVER_BASE = "http://<server-ip>:9000"
```

---

## 6. Step-by-Step Workflow

### Step 1 – Developer: create update package

```bash
# Create a zip file with your update payload
cd developer-tools
zip -r update_v1.2.3.zip my_app/
```

### Step 2 – Developer: sign and submit

```bash
python sign_update.py \
  --file update_v1.2.3.zip \
  --version 1.2.3 \
  --server http://192.168.56.103:9000 \
  --submitted-by alice

# Or dry-run (sign only, no network):
python sign_update.py --file update_v1.2.3.zip --version 1.2.3 --dry-run
```

**What happens inside:**
1. SHA-256 of the ZIP is computed
2. The hex string is signed with `pki/dev_private.key` (RSA-PKCS1v15/SHA-256)
3. A multipart POST is sent to `/submit` with: ZIP, dev cert, signature, SHA-256
4. Server verifies everything; update goes to PENDING

### Step 3 – Release Manager: approve

```bash
curl -X POST http://192.168.56.103:9000/approve \
     -H "X-Admin-Token: changeme-secret-token" \
     -F "version=1.2.3" \
     -F "approved_by=bob-release-manager"
```

**What happens inside:**
- Admin token checked
- Rollback check: 1.2.3 > current latest
- Release moved from `pending/` to `updates/`
- Manifest updated with integrity hash

### Step 4 – Client: detect and install update

```bash
cd client-app
python gui.py
```

Click **"Check for Updates"** → popup appears if update is available → click **"Download & Install"**.

**What happens inside (10 security checks):**
1. Fetch manifest → verify integrity hash
2. Compare semantic versions (rollback protection)
3. Download ZIP
4. Verify SHA-256
5. Fetch company cert from server
6. Verify cert fingerprint matches manifest entry
7. Verify cert chain (issuer == CA, CA signature valid, not expired)
8. Verify RSA signature over SHA-256
9. Final rollback protection check
10. Safe ZIP extraction with Zip Slip prevention

---

## 7. API Reference

### `POST /submit`

| Field | Type | Description |
|-------|------|-------------|
| `version` | form string | Semantic version (e.g. `1.2.3`) |
| `expected_sha256` | form string | 64-char SHA-256 hex of the ZIP |
| `update_file` | file | The update ZIP archive |
| `dev_cert` | file | Developer PEM certificate (signed by CA) |
| `signature` | file | Base64-encoded RSA signature |
| `submitted_by` | form string | Identifier for audit log |

Response: `{"status": "pending", "version": "1.2.3", "sha256": "..."}`

### `POST /approve`

| Field | Type | Description |
|-------|------|-------------|
| `version` | form string | Version to approve |
| `approved_by` | form string | Identifier for audit log |
| `X-Admin-Token` | header | Admin secret token |

Response: `{"status": "released", "version": "1.2.3", "latest_version": "1.2.3"}`

### `GET /manifest.json`

Returns the full release manifest including:
- `latest_version`
- `releases` dictionary with per-version: `sha256`, `signature_b64`, `cert_fingerprint_sha256`, `cert_subject`, `approved_by`, `approved_at`
- `_integrity` – SHA-256 of the manifest payload (tamper detection)

### `GET /updates/<version>/<filename>`

Download approved update archive.

### `GET /pending` (admin)

List pending submissions. Requires `X-Admin-Token` header.

---

## 8. Security Design Decisions

### Why sign the SHA-256 hex, not the raw file?

Signing `sha256hex.encode("utf-8")` means:
- The signature payload is always 64 bytes, regardless of file size
- The client can verify without re-streaming the whole file
- The same bytes are signed by the developer and verified by the server and the client
- The hash and signature together bind the identity to the exact file contents

### Why is the CA cert on the server disk (not submitted)?

If the server accepted the CA cert as a form field, an attacker could generate their own CA + developer cert pair and submit an arbitrary update. By keeping the CA cert on disk (out of band), we enforce that only certs signed by our specific CA are trusted.

### Why two-phase (submit + approve)?

A single-step publish flow would allow a compromised developer account to push malicious updates directly to clients. The approval gate means:
- An attacker who steals a developer key can only reach PENDING
- A Release Manager with a separate credential must approve
- This is separation of duties per ISO 27001 A.5.3

### Why semantic version comparison for rollback protection?

String comparison (`"1.9.0" > "1.10.0"`) would give wrong results. We parse `(major, minor, patch)` tuples and compare numerically, which correctly identifies 1.10.0 as newer than 1.9.0.

---

## 9. Security Assumptions and Known Limitations

| Assumption | Implication |
|------------|-------------|
| The CA private key is kept secret | If compromised, all trust is broken |
| The CA cert distributed to clients is authentic | If swapped, attacker becomes the CA |
| The admin token is secret | Use mTLS or HSM in production |
| The channel uses TLS | Without HTTPS, SHA-256 and metadata can be observed (but not modified undetectably) |
| The client machine is not compromised | Post-exploitation is out of scope |

**Known Limitations (lab scope):**
- No Certificate Revocation List (CRL) or OCSP – a revoked developer cert remains trusted until expiry
- Admin token is a static shared secret – production should use short-lived JWT or mTLS
- No multi-admin approval threshold (could add M-of-N signing)
- No rate limiting on /submit
- No binary transparency log (Sigstore/Rekor integration would add this)

---

## 10. Future Improvements

| Feature | Benefit |
|---------|---------|
| OCSP / CRL support | Revoke compromised developer certs immediately |
| RSA-PSS instead of PKCS1v15 | Stronger padding (provably secure) |
| mTLS for /approve | Replace admin token with certificate authentication |
| Sigstore / Rekor integration | Immutable transparency log of all releases |
| M-of-N release approval | Two Release Managers must approve (threshold signing) |
| Delta updates | Ship only changed files (bandwidth efficiency) |
| Ed25519 signatures | Faster, smaller signatures than RSA |
| Automated client rollback test | CI/CD gate: attempt downgrade, assert rejection |
| HSM for CA private key | Hardware-level protection for the root of trust |
| SBOM (Software Bill of Materials) | Supply chain transparency per NIST EO 14028 |

---

*This project is designed for educational purposes to demonstrate production PKI architecture, certificate chain validation, digital signatures, and secure update distribution principles.*
