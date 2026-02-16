import os
import json
import time
import hashlib
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

APP = FastAPI(title="Simple PKI Update Server")

BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
UPDATES_DIR = STORAGE_DIR / "updates"
MANIFEST_PATH = STORAGE_DIR / "manifest.json"

# Put your CA certificate here (PEM). Example: storage/ca_cert.pem
CA_CERT_PATH = STORAGE_DIR / "ca_cert.pem"

UPDATES_DIR.mkdir(parents=True, exist_ok=True)
STORAGE_DIR.mkdir(parents=True, exist_ok=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_ca_cert() -> x509.Certificate:
    if not CA_CERT_PATH.exists():
        raise RuntimeError(f"CA certificate not found: {CA_CERT_PATH}")
    ca_pem = CA_CERT_PATH.read_bytes()
    return x509.load_pem_x509_certificate(ca_pem)


def verify_cert_signed_by_ca(company_cert_pem: bytes, ca_cert: x509.Certificate) -> x509.Certificate:
    """
    Verifies the company certificate is:
    - within validity period
    - signed by the CA certificate you trust
    """
    try:
        company_cert = x509.load_pem_x509_certificate(company_cert_pem)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid company certificate PEM: {e}")

    now = time.time()
    if company_cert.not_valid_before_utc.timestamp() > now or company_cert.not_valid_after_utc.timestamp() < now:
        raise HTTPException(status_code=400, detail="Company certificate is expired or not yet valid")

    # Basic issuer check (not sufficient alone, but good sanity)
    if company_cert.issuer != ca_cert.subject:
        raise HTTPException(status_code=400, detail="Company certificate issuer does not match CA subject")

    # Cryptographic signature verification: CA public key verifies cert signature
    ca_public_key = ca_cert.public_key()
    try:
        ca_public_key.verify(
            company_cert.signature,
            company_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),  # typical for RSA CA certs
            company_cert.signature_hash_algorithm,
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Company certificate is NOT signed by the trusted CA")

    return company_cert


def read_manifest() -> dict:
    if MANIFEST_PATH.exists():
        return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    return {"latest": None, "releases": []}


def write_manifest(data: dict) -> None:
    MANIFEST_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


@APP.post("/publish")
async def publish_update(
    version: str = Form(...),
    expected_sha256: str = Form(...),
    update_file: UploadFile = File(...),
    company_cert: UploadFile = File(...),
):
    # 1) Basic checks
    if not version.strip():
        raise HTTPException(status_code=400, detail="version is required")

    expected_sha256 = expected_sha256.strip().lower()
    if len(expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in expected_sha256):
        raise HTTPException(status_code=400, detail="expected_sha256 must be a valid sha256 hex string")

    # 2) Verify company cert is signed by our CA
    ca_cert = load_ca_cert()
    company_cert_pem = await company_cert.read()
    verified_company_cert = verify_cert_signed_by_ca(company_cert_pem, ca_cert)

    # 3) Save uploaded update file to disk (versioned folder)
    release_dir = UPDATES_DIR / version
    release_dir.mkdir(parents=True, exist_ok=True)

    safe_name = os.path.basename(update_file.filename or "update.bin")
    artifact_path = release_dir / safe_name

    content = await update_file.read()
    artifact_path.write_bytes(content)

    # 4) Verify SHA256 matches what publisher claimed
    actual_sha256 = sha256_file(artifact_path)
    if actual_sha256 != expected_sha256:
        # remove bad artifact
        try:
            artifact_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise HTTPException(
            status_code=400,
            detail=f"SHA256 mismatch. expected={expected_sha256} actual={actual_sha256}"
        )

    # 5) Store cert alongside the release (for audit)
    (release_dir / "company_cert.pem").write_bytes(company_cert_pem)

    # 6) Update manifest
    manifest = read_manifest()
    entry = {
        "version": version,
        "filename": safe_name,
        "sha256": actual_sha256,
        "uploaded_at": int(time.time()),
        "company_cert_subject": verified_company_cert.subject.rfc4514_string(),
    }

    # replace if same version exists
    manifest["releases"] = [r for r in manifest["releases"] if r.get("version") != version]
    manifest["releases"].append(entry)
    manifest["latest"] = version
    write_manifest(manifest)

    return JSONResponse(
        {
            "status": "ok",
            "latest": manifest["latest"],
            "release": entry,
            "download_url": f"/updates/{version}/{safe_name}",
        }
    )


@APP.get("/manifest.json")
def get_manifest():
    return JSONResponse(read_manifest())


# Serve update files
APP.mount("/updates", StaticFiles(directory=str(UPDATES_DIR)), name="updates")
