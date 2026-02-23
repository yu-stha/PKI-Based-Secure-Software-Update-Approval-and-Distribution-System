"""
PKI-Based Secure Software Update Server  v2.0
==============================================
Two-phase update distribution system:

  Phase 1 – /submit  : Developer uploads signed update → stored as PENDING
  Phase 2 – /approve : Release Manager promotes pending update → RELEASED

Security controls implemented
-------------------------------
[NIST SI-7]   Software/Firmware Integrity – cert chain + signature verification
[NIST AC-3]   Access Enforcement         – separate submit vs approve roles
[NIST AU-2]   Audit Events               – structured audit.log for every action
[ISO A.8.32]  Change Management          – approval gate before distribution
[Supply-chain] Trust anchor on server disk; submitted cert cannot be self-signed CA
[Rollback]    /approve rejects version <= current latest (downgrade protection)
[Traversal]   Filenames sanitised before writing to disk
"""

import base64
import hashlib
import json
import logging
import os
import re
import shutil
import time
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, UploadFile, File, Header
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ---------------------------------------------------------------------------
# Directory layout
# ---------------------------------------------------------------------------
BASE_DIR      = Path(__file__).resolve().parent
STORAGE_DIR   = BASE_DIR / "storage"
PENDING_DIR   = STORAGE_DIR / "pending"
UPDATES_DIR   = STORAGE_DIR / "updates"
MANIFEST_PATH = STORAGE_DIR / "manifest.json"
AUDIT_LOG     = STORAGE_DIR / "logs" / "audit.log"
# Trust anchor – CA cert lives on the server, NOT provided by submitter
CA_CERT_PATH  = BASE_DIR / "pki" / "ca_cert.pem"

for _d in (PENDING_DIR, UPDATES_DIR, STORAGE_DIR / "logs"):
    _d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Audit logger
# ---------------------------------------------------------------------------
logger = logging.getLogger("pki-update-server")
logger.setLevel(logging.INFO)
_sh = logging.StreamHandler()
_sh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(_sh)
_fh = logging.FileHandler(AUDIT_LOG, encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s [AUDIT] %(message)s"))
logger.addHandler(_fh)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
# [NIST AC-3] In production use mTLS or short-lived OAuth2 client tokens
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "changeme-secret-token")

SEM_VER_RE = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*))?$"
)

APP = FastAPI(title="PKI Secure Update Server", version="2.0.0")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def safe_filename(name: str) -> str:
    """[SI-7] Strip directory components and restrict to safe charset."""
    name = os.path.basename(name or "update.zip")
    name = re.sub(r"[^a-zA-Z0-9_.\-]", "_", name)
    return name or "update.zip"


def parse_version(v: str) -> tuple:
    """Return (major, minor, patch) tuple for numeric comparison."""
    m = SEM_VER_RE.match(v.strip())
    if not m:
        raise HTTPException(
            400, f"Invalid semantic version: {v!r}. Expected MAJOR.MINOR.PATCH"
        )
    return (int(m.group("major")), int(m.group("minor")), int(m.group("patch")))


def load_ca_cert() -> x509.Certificate:
    if not CA_CERT_PATH.exists():
        raise RuntimeError(
            f"CA certificate not found at {CA_CERT_PATH}. "
            "Run developer-tools/generate_ca.py first."
        )
    return x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())


def verify_cert_chain(dev_cert_pem: bytes, ca_cert: x509.Certificate) -> x509.Certificate:
    """
    [SI-7] Validates developer certificate against the trusted CA:

    1. Parse PEM (reject garbage)
    2. Check validity window (not expired, not future-dated)
    3. Verify issuer == CA subject (prevents self-signed abuse)
    4. Verify CA's RSA signature over TBS bytes

    The trust anchor (CA cert) lives on SERVER DISK and is never supplied
    by the submitter – this defeats supply-chain attacks where an attacker
    generates their own CA and developer cert pair.
    """
    try:
        dev_cert = x509.load_pem_x509_certificate(dev_cert_pem)
    except Exception as e:
        raise HTTPException(400, f"Cannot parse developer certificate PEM: {e}")

    now = time.time()
    if dev_cert.not_valid_before_utc.timestamp() > now:
        raise HTTPException(400, "Developer certificate is not yet valid")
    if dev_cert.not_valid_after_utc.timestamp() < now:
        raise HTTPException(400, "Developer certificate has EXPIRED")

    # Issuer binding – if issuer != CA subject the cert was signed by someone else
    if dev_cert.issuer != ca_cert.subject:
        raise HTTPException(
            400,
            "Certificate issuer does not match trusted CA subject → "
            "supply-chain integrity check FAILED"
        )

    try:
        ca_cert.public_key().verify(
            dev_cert.signature,
            dev_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            dev_cert.signature_hash_algorithm,
        )
    except Exception:
        raise HTTPException(
            400, "Certificate signature invalid – NOT signed by the trusted CA"
        )

    return dev_cert


def decode_signature(raw: bytes) -> bytes:
    """Accept base64-encoded or raw binary signatures (curl uploads vary)."""
    try:
        return base64.b64decode(raw.strip(), validate=True)
    except Exception:
        return raw


def verify_update_signature(
    dev_cert: x509.Certificate,
    sig_bytes: bytes,
    sha256_hex: str,
) -> None:
    """
    [SI-7] Verify RSA-PKCS1v15/SHA-256 signature over the file's SHA-256 hex.

    Signing the hex-encoded hash means:
    - Clients can verify without re-downloading the full file
    - The exact same bytes are signed on publish and verified on client
    """
    pub = dev_cert.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        raise HTTPException(400, "Only RSA developer certificates are supported")
    try:
        pub.verify(
            sig_bytes,
            sha256_hex.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception:
        raise HTTPException(
            400,
            "Signature verification FAILED – update file not signed by provided certificate"
        )


def read_manifest() -> dict:
    """Load manifest and verify its integrity hash on every read. [SI-7]"""
    if MANIFEST_PATH.exists():
        try:
            data   = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            stored = data.pop("_integrity", None)
            computed = sha256_bytes(json.dumps(data, sort_keys=True).encode())
            if stored and stored != computed:
                logger.warning(
                    "MANIFEST INTEGRITY MISMATCH stored=%s computed=%s",
                    stored, computed,
                )
            data["_integrity"] = stored
            return data
        except Exception:
            pass
    return {"latest_version": None, "releases": {}}


def write_manifest(data: dict) -> None:
    """Write manifest atomically; embed integrity hash. [SI-7]"""
    payload  = {k: v for k, v in data.items() if k != "_integrity"}
    payload["_integrity"] = sha256_bytes(
        json.dumps(payload, sort_keys=True).encode()
    )
    tmp = MANIFEST_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(MANIFEST_PATH)   # atomic rename on POSIX


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@APP.post("/submit", summary="Developer submits a signed update (→ PENDING)")
async def submit_update(
    version:         str        = Form(..., description="Semantic version e.g. 1.2.3"),
    expected_sha256: str        = Form(..., description="SHA-256 hex of the ZIP"),
    update_file:     UploadFile = File(..., description="The update ZIP archive"),
    dev_cert:        UploadFile = File(..., description="Developer PEM cert signed by CA"),
    signature:       UploadFile = File(..., description="Detached RSA signature (base64 or raw)"),
    submitted_by:    str        = Form("anonymous", description="Identifier for audit log"),
):
    """
    Security pipeline – ALL steps must pass before storing the file:

    Step 1  Version format validation (reject non-semver)
    Step 2  SHA-256 format validation
    Step 3  Certificate chain validation (CA trust anchor check)
    Step 4  File name sanitisation (path traversal prevention)
    Step 5  Write file to disk
    Step 6  Verify actual SHA-256 == declared SHA-256
    Step 7  Verify RSA signature over SHA-256 with developer cert
    Step 8  Persist audit artefacts (cert, sig, meta)

    The update goes into PENDING – clients cannot download it yet.
    """

    # Step 1 – version
    parse_version(version)

    # Step 2 – sha256 format
    expected_sha256 = expected_sha256.strip().lower()
    if len(expected_sha256) != 64 or not all(
        c in "0123456789abcdef" for c in expected_sha256
    ):
        raise HTTPException(400, "expected_sha256 must be a 64-char lowercase hex string")

    # Step 3 – cert chain
    ca_cert       = load_ca_cert()
    dev_cert_pem  = await dev_cert.read()
    verified_cert = verify_cert_chain(dev_cert_pem, ca_cert)

    # Step 4 – safe filename
    safe_name   = safe_filename(update_file.filename)
    pending_dir = PENDING_DIR / version
    pending_dir.mkdir(parents=True, exist_ok=True)
    artifact    = pending_dir / safe_name

    # Step 5 – write file
    artifact.write_bytes(await update_file.read())

    # Step 6 – hash check
    actual_sha256 = sha256_file(artifact)
    if actual_sha256 != expected_sha256:
        artifact.unlink(missing_ok=True)
        raise HTTPException(
            400,
            f"SHA-256 mismatch: declared={expected_sha256} actual={actual_sha256}"
        )

    # Step 7 – signature
    sig_raw = decode_signature(await signature.read())
    verify_update_signature(verified_cert, sig_raw, actual_sha256)

    # Step 8 – audit artefacts
    sig_b64 = base64.b64encode(sig_raw).decode()
    (pending_dir / "dev_cert.pem").write_bytes(dev_cert_pem)
    (pending_dir / "signature.b64").write_text(sig_b64, encoding="utf-8")
    meta = {
        "version":                 version,
        "filename":                safe_name,
        "sha256":                  actual_sha256,
        "signature_b64":           sig_b64,
        "cert_fingerprint_sha256": sha256_bytes(dev_cert_pem),
        "cert_subject":            verified_cert.subject.rfc4514_string(),
        "cert_not_after":          verified_cert.not_valid_after_utc.isoformat(),
        "submitted_by":            submitted_by,
        "submitted_at":            int(time.time()),
        "status":                  "pending",
    }
    (pending_dir / "meta.json").write_text(json.dumps(meta, indent=2))

    logger.info(
        "SUBMIT ok  version=%s sha256=%s cert=%s by=%s",
        version, actual_sha256, meta["cert_subject"], submitted_by,
    )
    return JSONResponse({
        "status":  "pending",
        "version": version,
        "sha256":  actual_sha256,
        "message": "Awaiting release-manager approval via /approve",
    })


@APP.post("/approve", summary="Release manager approves a pending update")
async def approve_update(
    version:       str = Form(...),
    approved_by:   str = Form("release-manager"),
    x_admin_token: str = Header(..., alias="X-Admin-Token"),
):
    """
    [NIST AC-3 / Insider-threat mitigation]
    Intentional separation of duties:
      • Developers can SUBMIT but cannot APPROVE
      • Release Managers approve using a separate credential

    [SI-7 Rollback protection]
    Approval is rejected when version ≤ current latest_version,
    preventing an attacker (or insider) from re-publishing an old
    vulnerable version.
    """
    if x_admin_token != ADMIN_TOKEN:
        logger.warning(
            "APPROVE DENIED invalid-token version=%s attempted_by=%s",
            version, approved_by,
        )
        raise HTTPException(403, "Invalid admin token")

    parse_version(version)

    meta_path = PENDING_DIR / version / "meta.json"
    if not meta_path.exists():
        raise HTTPException(404, f"No pending submission for version {version!r}")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))

    # Downgrade / rollback check
    manifest = read_manifest()
    current  = manifest.get("latest_version")
    if current:
        try:
            if parse_version(version) <= parse_version(current):
                raise HTTPException(
                    409,
                    f"Rollback rejected: {version} is not strictly newer than "
                    f"current latest {current}"
                )
        except HTTPException:
            raise

    # Move pending → updates
    dest = UPDATES_DIR / version
    if dest.exists():
        shutil.rmtree(dest)
    shutil.move(str(PENDING_DIR / version), str(dest))

    # Update manifest
    meta.update({
        "status":      "released",
        "approved_by": approved_by,
        "approved_at": int(time.time()),
    })
    releases = manifest.get("releases", {})
    releases[version] = meta
    manifest["releases"]       = releases
    manifest["latest_version"] = version
    write_manifest(manifest)

    logger.info("APPROVE ok  version=%s by=%s", version, approved_by)
    return JSONResponse({
        "status":         "released",
        "version":        version,
        "latest_version": version,
    })


@APP.get("/manifest.json", summary="Public release manifest")
def get_manifest():
    return JSONResponse(read_manifest())


@APP.get("/pending", summary="List pending submissions (admin only)")
def list_pending(x_admin_token: str = Header(..., alias="X-Admin-Token")):
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(403, "Invalid admin token")
    result = []
    for d in sorted(PENDING_DIR.iterdir()):
        mf = d / "meta.json"
        if mf.exists():
            result.append(json.loads(mf.read_text()))
    return JSONResponse(result)


@APP.get("/health")
def health():
    return {"status": "ok", "timestamp": int(time.time())}


# Serve released update archives via GET /updates/<version>/<filename>
APP.mount("/updates", StaticFiles(directory=str(UPDATES_DIR)), name="updates")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(APP, host="0.0.0.0", port=9000)
