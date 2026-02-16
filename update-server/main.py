import os
import json
import time
import hashlib
import base64
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

APP = FastAPI(title="Simple PKI Update Server")

BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
UPDATES_DIR = STORAGE_DIR / "updates"
MANIFEST_PATH = STORAGE_DIR / "manifest.json"

# Trusted CA certificate used to validate publisher company cert
CA_CERT_PATH = STORAGE_DIR / "ca_cert.pem"

UPDATES_DIR.mkdir(parents=True, exist_ok=True)
STORAGE_DIR.mkdir(parents=True, exist_ok=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load_ca_cert() -> x509.Certificate:
    if not CA_CERT_PATH.exists():
        raise RuntimeError(f"CA certificate not found: {CA_CERT_PATH}")
    ca_pem = CA_CERT_PATH.read_bytes()
    return x509.load_pem_x509_certificate(ca_pem)


def verify_cert_signed_by_ca(company_cert_pem: bytes, ca_cert: x509.Certificate) -> x509.Certificate:
    """
    Verifies the company certificate is:
    - within validity period
    - issued/signed by trusted CA
    """
    try:
        company_cert = x509.load_pem_x509_certificate(company_cert_pem)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid company certificate PEM: {e}")

    now = time.time()
    if company_cert.not_valid_before_utc.timestamp() > now or company_cert.not_valid_after_utc.timestamp() < now:
        raise HTTPException(status_code=400, detail="Company certificate is expired or not yet valid")

    if company_cert.issuer != ca_cert.subject:
        raise HTTPException(status_code=400, detail="Company certificate issuer does not match CA subject")

    ca_public_key = ca_cert.public_key()
    try:
        ca_public_key.verify(
            company_cert.signature,
            company_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            company_cert.signature_hash_algorithm,
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Company certificate is NOT signed by the trusted CA")

    return company_cert


def decode_signature(sig_bytes: bytes) -> bytes:
    """
    Accepts either:
    - raw signature bytes
    - base64 text (common for curl uploads)
    Returns raw signature bytes.
    """
    s = sig_bytes.strip()
    # try base64 decode first (most likely)
    try:
        # validate=True ensures it fails fast if not base64
        return base64.b64decode(s, validate=True)
    except Exception:
        # fallback: treat as raw signature bytes
        return sig_bytes


def verify_update_signature(company_cert: x509.Certificate, signature_raw: bytes, sha256_hex: str) -> None:
    """
    Verifies signature over the sha256 hex string (UTF-8 bytes).
    Publisher signs a file containing the sha256 hex string using:
      openssl dgst -sha256 -sign company_private.key -out update.sig update.sha256
    """
    pub = company_cert.public_key()

    # Keep it simple for the lab: RSA + PKCS#1 v1.5
    if not isinstance(pub, rsa.RSAPublicKey):
        raise HTTPException(status_code=400, detail="Only RSA company certificates are supported in this lab setup")

    data = sha256_hex.encode("utf-8")
    try:
        pub.verify(
            signature_raw,
            data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid signature: update is not signed by the provided company certificate")


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
    signature: UploadFile = File(...),  # NEW
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

    # 3) Save uploaded update file to disk
    release_dir = UPDATES_DIR / version
    release_dir.mkdir(parents=True, exist_ok=True)

    safe_name = os.path.basename(update_file.filename or "update.bin")
    artifact_path = release_dir / safe_name

    content = await update_file.read()
    artifact_path.write_bytes(content)

    # 4) Verify SHA256 matches what publisher claimed
    actual_sha256 = sha256_file(artifact_path)
    if actual_sha256 != expected_sha256:
        try:
            artifact_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise HTTPException(
            status_code=400,
            detail=f"SHA256 mismatch. expected={expected_sha256} actual={actual_sha256}"
        )

    # 5) Verify signature (NEW)
    sig_upload = await signature.read()
    sig_raw = decode_signature(sig_upload)
    verify_update_signature(verified_company_cert, sig_raw, actual_sha256)

    # 6) Store cert + signature alongside the release (audit)
    (release_dir / "company_cert.pem").write_bytes(company_cert_pem)
    (release_dir / "signature.bin").write_bytes(sig_raw)
    (release_dir / "signature.b64").write_text(base64.b64encode(sig_raw).decode("ascii"), encoding="utf-8")

    # 7) Update manifest
    manifest = read_manifest()

    cert_fp = sha256_bytes(company_cert_pem)
    entry = {
        "version": version,
        "filename": safe_name,
        "sha256": actual_sha256,
        "signature_b64": base64.b64encode(sig_raw).decode("ascii"),
        "cert_fingerprint_sha256": cert_fp,
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


APP.mount("/updates", StaticFiles(directory=str(UPDATES_DIR)), name="updates")
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(APP, host="0.0.0.0", port=9000)
