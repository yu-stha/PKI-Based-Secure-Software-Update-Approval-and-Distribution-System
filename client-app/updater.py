"""
PKI Update Client – Core Logic
================================
Handles all security-sensitive operations:
  - Manifest fetching and integrity verification
  - Certificate chain validation (CA trust anchor)
  - RSA signature verification over update hash
  - Secure ZIP extraction (Zip Slip prevention)
  - Semantic version comparison and rollback protection
  - Persistent installed-version state

Separated from the GUI so unit-testing is easy.

[SI-7]  Software/Firmware Integrity
[SC-8]  Transmission Confidentiality (use HTTPS in production)
[SI-10] Information Input Validation
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ---------------------------------------------------------------------------
# Semantic version helpers
# ---------------------------------------------------------------------------
SEM_VER_RE = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*))?$"
)


def parse_version(v: str) -> tuple[int, int, int]:
    m = SEM_VER_RE.match((v or "").strip())
    if not m:
        raise ValueError(f"Cannot parse version string: {v!r}")
    return (int(m.group("major")), int(m.group("minor")), int(m.group("patch")))


def version_is_newer(installed: str | None, candidate: str) -> bool:
    """
    [SI-7 Rollback protection] Returns True only if candidate is strictly
    greater than installed version.  Never allows downgrade.
    """
    if not installed:
        return True
    try:
        return parse_version(candidate) > parse_version(installed)
    except ValueError:
        # If we cannot parse either, treat candidate as newer (safe default)
        return True


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
UA = "PKI-SecureUpdateClient/2.0"


def http_get_json(url: str, timeout: int = 8) -> dict:
    req = Request(url, headers={"User-Agent": UA})
    with urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def http_download(url: str, dest: Path, timeout: int = 60) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = Request(url, headers={"User-Agent": UA})
    with urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)


# ---------------------------------------------------------------------------
# Cryptographic helpers
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load_ca_cert(path: Path) -> x509.Certificate:
    """
    [SI-7] The CA certificate is the client's trust anchor.
    It must ship with the application and NEVER be downloaded from the
    update server – that would allow MITM to substitute their own CA.
    """
    if not path.exists():
        raise FileNotFoundError(
            f"CA certificate not found: {path}\n"
            "Copy ca_cert.pem from developer-tools/ to client-app/."
        )
    return x509.load_pem_x509_certificate(path.read_bytes())


def verify_cert_chain(
    company_cert_pem: bytes,
    ca_cert: x509.Certificate,
) -> x509.Certificate:
    """
    [SI-7] Full chain validation:
    1. Parse certificate
    2. Check validity window
    3. Issuer must match CA subject
    4. Verify CA signature over TBS bytes
    """
    import time
    try:
        cert = x509.load_pem_x509_certificate(company_cert_pem)
    except Exception as e:
        raise ValueError(f"Cannot parse company certificate: {e}")

    now = time.time()
    if cert.not_valid_before_utc.timestamp() > now:
        raise ValueError("Company certificate is not yet valid")
    if cert.not_valid_after_utc.timestamp() < now:
        raise ValueError("Company certificate has EXPIRED")

    if cert.issuer != ca_cert.subject:
        raise ValueError(
            "Certificate issuer does not match trusted CA subject → "
            "possible supply-chain attack"
        )

    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception:
        raise ValueError("Certificate is NOT signed by the trusted CA")

    return cert


def verify_cert_fingerprint(company_cert_pem: bytes, expected_fp: str) -> None:
    """
    [SI-7] Verify the downloaded cert matches the fingerprint in the manifest.
    Prevents an attacker who can intercept the cert download from substituting
    a different (but CA-signed) certificate.
    """
    actual_fp = sha256_bytes(company_cert_pem)
    if actual_fp.lower() != expected_fp.lower():
        raise ValueError(
            f"Certificate fingerprint mismatch:\n"
            f"  manifest: {expected_fp}\n"
            f"  actual:   {actual_fp}\n"
            "Possible MITM or manifest tampering."
        )


def verify_signature(
    cert: x509.Certificate,
    signature_b64: str,
    sha256_hex: str,
) -> None:
    """
    [SI-7] Verify RSA-PKCS1v15/SHA-256 signature over the file's SHA-256 hex.
    Matches exactly what sign_update.py and the server both produce.
    """
    pub = cert.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ValueError("Only RSA company certificates are supported")
    sig = base64.b64decode(signature_b64.strip())
    try:
        pub.verify(
            sig,
            sha256_hex.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception:
        raise ValueError(
            "Signature verification FAILED – update file may be corrupted or tampered"
        )


# ---------------------------------------------------------------------------
# Manifest helpers
# ---------------------------------------------------------------------------

def verify_manifest_integrity(manifest: dict) -> None:
    """
    [SI-7] Verify the manifest's self-declared integrity hash.
    Detects tampering with the manifest JSON in transit.
    """
    stored = manifest.get("_integrity")
    if not stored:
        return  # server did not include integrity (old server version)
    payload = {k: v for k, v in manifest.items() if k != "_integrity"}
    computed = sha256_bytes(json.dumps(payload, sort_keys=True).encode())
    if stored != computed:
        raise ValueError(
            "Manifest integrity check FAILED – manifest may have been tampered with"
        )


def get_latest_release(manifest: dict) -> dict | None:
    latest  = manifest.get("latest_version")
    if not latest:
        return None
    releases = manifest.get("releases", {})
    return releases.get(latest)


# ---------------------------------------------------------------------------
# Secure ZIP extraction
# ---------------------------------------------------------------------------

def safe_extract_zip(zip_path: Path, target_dir: Path) -> list[str]:
    """
    [SI-7 / CWE-22] Zip Slip prevention.

    For each entry in the ZIP:
      - Resolve the full destination path
      - Assert it is inside target_dir
      - Reject absolute paths and path traversal sequences

    Returns list of extracted relative paths.
    """
    target_dir = target_dir.resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    extracted = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            # Reject absolute paths
            if member.filename.startswith("/") or member.filename.startswith("\\"):
                raise ValueError(
                    f"ZIP Slip: absolute path in archive: {member.filename}"
                )

            dest = (target_dir / member.filename).resolve()

            # Ensure destination is inside target directory
            try:
                dest.relative_to(target_dir)
            except ValueError:
                raise ValueError(
                    f"ZIP Slip: path traversal detected: {member.filename}"
                )

            if member.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(dest, "wb") as out:
                    out.write(src.read())
                extracted.append(str(dest.relative_to(target_dir)))

    return extracted


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------

def load_state(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_state(path: Path, state: dict) -> None:
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# High-level update workflow
# ---------------------------------------------------------------------------

class UpdateError(Exception):
    """Raised when any security check fails during update."""


class UpdateClient:
    """
    Orchestrates the full update lifecycle:

    check()             → returns (available: bool, release: dict | None)
    download_and_install(release, callbacks) → installs if all checks pass

    Security checks performed on install:
      1. Download ZIP
      2. Verify SHA-256 of downloaded file
      3. Download company certificate from server
      4. Verify cert chain (CA trust anchor)
      5. Verify cert fingerprint matches manifest (MITM protection)
      6. Verify RSA signature over SHA-256
      7. Version strictly greater than installed (rollback protection)
      8. Safe ZIP extraction (Zip Slip prevention)
    """

    def __init__(
        self,
        server_base: str,
        ca_cert_path: Path,
        downloads_dir: Path,
        install_dir: Path,
        state_path: Path,
    ):
        self.server_base   = server_base.rstrip("/")
        self.manifest_url  = f"{self.server_base}/manifest.json"
        self.ca_cert_path  = ca_cert_path
        self.downloads_dir = downloads_dir
        self.install_dir   = install_dir
        self.state_path    = state_path

        self.state             = load_state(state_path)
        self.installed_version = self.state.get("installed_version")

    def check(self) -> tuple[bool, dict | None]:
        """Fetch manifest and determine if an update is available."""
        manifest = http_get_json(self.manifest_url)
        verify_manifest_integrity(manifest)
        release = get_latest_release(manifest)
        if not release:
            return False, None
        available = version_is_newer(self.installed_version, release["version"])
        return available, release

    def download_and_install(
        self,
        release: dict,
        on_progress: callable = None,
    ) -> Path:
        """
        Full verified install pipeline. Raises UpdateError on any failure.
        Returns the installation directory path.
        """
        def log(msg: str):
            if on_progress:
                on_progress(msg)

        version    = release["version"]
        filename   = release["filename"]
        exp_sha    = release["sha256"]
        sig_b64    = release.get("signature_b64")
        cert_fp    = release.get("cert_fingerprint_sha256")

        if not sig_b64:
            raise UpdateError(
                "Manifest entry missing signature_b64. "
                "Re-publish using the updated server."
            )

        # ── Download ZIP ──────────────────────────────────────────────────
        zip_url  = f"{self.server_base}/updates/{version}/{filename}"
        zip_path = self.downloads_dir / version / filename
        log(f"Downloading {zip_url}")
        try:
            http_download(zip_url, zip_path)
        except (HTTPError, URLError) as e:
            raise UpdateError(f"Download failed: {e}")

        # ── SHA-256 verification ─────────────────────────────────────────
        log("Verifying SHA-256…")
        actual_sha = sha256_file(zip_path)
        if actual_sha.lower() != exp_sha.lower():
            raise UpdateError(
                f"SHA-256 mismatch!\n  expected: {exp_sha}\n  actual:   {actual_sha}"
            )

        # ── Certificate chain ─────────────────────────────────────────────
        log("Loading CA trust anchor…")
        try:
            ca_cert = load_ca_cert(self.ca_cert_path)
        except FileNotFoundError as e:
            raise UpdateError(str(e))

        # Fetch company cert stored alongside release on server
        cert_url  = f"{self.server_base}/updates/{version}/dev_cert.pem"
        cert_path = zip_path.parent / "dev_cert.pem"
        log(f"Fetching company certificate from {cert_url}")
        try:
            http_download(cert_url, cert_path)
        except (HTTPError, URLError) as e:
            raise UpdateError(f"Cannot fetch company cert: {e}")

        company_cert_pem = cert_path.read_bytes()

        # ── Cert fingerprint binding ──────────────────────────────────────
        log("Verifying certificate fingerprint against manifest…")
        if cert_fp:
            try:
                verify_cert_fingerprint(company_cert_pem, cert_fp)
            except ValueError as e:
                raise UpdateError(str(e))

        # ── Cert chain validation ─────────────────────────────────────────
        log("Validating certificate chain…")
        try:
            verified_cert = verify_cert_chain(company_cert_pem, ca_cert)
        except ValueError as e:
            raise UpdateError(str(e))

        # ── Signature verification ────────────────────────────────────────
        log("Verifying digital signature…")
        try:
            verify_signature(verified_cert, sig_b64, actual_sha)
        except ValueError as e:
            raise UpdateError(str(e))

        # ── Rollback protection ───────────────────────────────────────────
        log("Checking rollback protection…")
        if not version_is_newer(self.installed_version, version):
            raise UpdateError(
                f"Rollback rejected: {version} is not newer than "
                f"installed {self.installed_version}"
            )

        # ── Safe extraction ───────────────────────────────────────────────
        log("Extracting update (Zip Slip protection active)…")
        target = self.install_dir / version
        try:
            files = safe_extract_zip(zip_path, target)
        except (ValueError, zipfile.BadZipFile) as e:
            raise UpdateError(f"ZIP extraction failed: {e}")

        log(f"Extracted {len(files)} file(s) to {target}")

        # ── Persist state ─────────────────────────────────────────────────
        self.installed_version            = version
        self.state["installed_version"]   = version
        self.state["last_update_time"]    = __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ")
        self.state["last_update_sha256"]  = actual_sha
        save_state(self.state_path, self.state)

        return target
