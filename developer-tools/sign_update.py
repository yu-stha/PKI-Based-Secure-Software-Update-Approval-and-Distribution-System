"""
sign_update.py – Sign an Update Package and Submit to the Update Server
========================================================================
Computes SHA-256 of the update ZIP, signs the hex string with the
developer private key, then POSTs all artefacts to /submit.

Usage:
  python sign_update.py --file update.zip --version 1.2.3
  python sign_update.py --file update.zip --version 1.2.3 --server http://localhost:9000
  python sign_update.py --file update.zip --version 1.2.3 --dry-run   # sign only, no upload

Prerequisites:
  pki/dev_private.key  – developer signing key
  pki/dev_cert.pem     – developer certificate signed by CA

Output (local):
  update.zip.sha256    – plaintext SHA-256 of the ZIP
  update.zip.sig.b64   – base64-encoded RSA-PKCS1v15/SHA-256 signature

Submit sends:
  version, expected_sha256, update_file, dev_cert, signature → /submit
"""

import argparse
import base64
import hashlib
import sys
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

PKI_DIR       = Path(__file__).resolve().parent / "pki"
DEV_KEY_PATH  = PKI_DIR / "dev_private.key"
DEV_CERT_PATH = PKI_DIR / "dev_cert.pem"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sign_sha256(sha256_hex: str, key_path: Path) -> bytes:
    """
    Sign the SHA-256 hex string (UTF-8 bytes) with RSA-PKCS1v15/SHA-256.
    Matches the verification logic in both the server and the client.
    """
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    data = sha256_hex.encode("utf-8")
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def multipart_post(url: str, fields: dict, files: dict) -> bytes:
    """
    Minimal multipart/form-data POST without third-party dependencies.
    fields: {name: value_str}
    files:  {name: (filename, bytes, content_type)}
    """
    import uuid
    boundary = uuid.uuid4().hex.encode("ascii")
    body_parts = []

    for name, value in fields.items():
        body_parts.append(
            b"--" + boundary + b"\r\n"
            + f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
            + str(value).encode("utf-8")
            + b"\r\n"
        )

    for name, (filename, data, ctype) in files.items():
        body_parts.append(
            b"--" + boundary + b"\r\n"
            + f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
            + f"Content-Type: {ctype}\r\n\r\n".encode()
            + data
            + b"\r\n"
        )

    body_parts.append(b"--" + boundary + b"--\r\n")
    body = b"".join(body_parts)

    req = Request(
        url,
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary.decode()}",
            "Content-Length": str(len(body)),
            "User-Agent": "PKI-sign-update/2.0",
        },
        method="POST",
    )
    with urlopen(req, timeout=30) as r:
        return r.read()


def main():
    parser = argparse.ArgumentParser(description="Sign and submit an update package")
    parser.add_argument("--file",         required=True, help="Path to update ZIP")
    parser.add_argument("--version",      required=True, help="Semantic version e.g. 1.2.3")
    parser.add_argument("--server",       default="http://192.168.56.103:9000")
    parser.add_argument("--submitted-by", default="developer")
    parser.add_argument("--dry-run",      action="store_true", help="Sign but do not submit")
    args = parser.parse_args()

    update_path = Path(args.file)
    if not update_path.exists():
        print(f"[!] File not found: {update_path}", file=sys.stderr)
        sys.exit(1)

    for p in (DEV_KEY_PATH, DEV_CERT_PATH):
        if not p.exists():
            print(f"[!] Missing: {p}", file=sys.stderr)
            print("    Run generate_ca.py and generate_dev_cert.py first.", file=sys.stderr)
            sys.exit(1)

    # 1 – Hash
    print(f"[*] Computing SHA-256 of {update_path.name}…")
    sha256_hex = sha256_file(update_path)
    print(f"    {sha256_hex}")

    sha_out = update_path.with_suffix(update_path.suffix + ".sha256")
    sha_out.write_text(sha256_hex, encoding="utf-8")
    print(f"    Saved → {sha_out}")

    # 2 – Sign
    print("[*] Signing SHA-256 with developer private key…")
    sig_raw  = sign_sha256(sha256_hex, DEV_KEY_PATH)
    sig_b64  = base64.b64encode(sig_raw).decode()
    sig_path = update_path.with_suffix(update_path.suffix + ".sig.b64")
    sig_path.write_text(sig_b64, encoding="utf-8")
    print(f"    Saved → {sig_path}")

    if args.dry_run:
        print()
        print("[✓] Dry-run complete. No file submitted.")
        return

    # 3 – Submit
    submit_url = f"{args.server.rstrip('/')}/submit"
    print(f"[*] Submitting to {submit_url}…")

    try:
        resp = multipart_post(
            submit_url,
            fields={
                "version":         args.version,
                "expected_sha256": sha256_hex,
                "submitted_by":    args.submitted_by,
            },
            files={
                "update_file": (update_path.name,     update_path.read_bytes(),   "application/zip"),
                "dev_cert":    (DEV_CERT_PATH.name,   DEV_CERT_PATH.read_bytes(), "application/x-pem-file"),
                "signature":   (sig_path.name,        sig_path.read_bytes(),      "application/octet-stream"),
            },
        )
    except HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"[!] HTTP {e.code}: {body}", file=sys.stderr)
        sys.exit(1)
    except URLError as e:
        print(f"[!] Connection error: {e}", file=sys.stderr)
        sys.exit(1)

    print()
    try:
        data = json.loads(resp)
        print(f"[✓] Server response: {json.dumps(data, indent=2)}")
    except Exception:
        print(f"[✓] Server response: {resp.decode()}")

    print()
    print(f"[i] Now ask your Release Manager to approve version {args.version}:")
    print(f'    curl -X POST {args.server}/approve \\')
    print(f'         -H "X-Admin-Token: <token>" \\')
    print(f'         -F "version={args.version}" \\')
    print(f'         -F "approved_by=release-manager"')


if __name__ == "__main__":
    main()
