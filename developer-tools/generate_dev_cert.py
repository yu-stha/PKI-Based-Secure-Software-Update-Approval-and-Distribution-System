"""
generate_dev_cert.py – Generate Developer Signing Certificate
=============================================================
Signs a new RSA-3072 key with the CA private key.

Prerequisites: run generate_ca.py first.

Output files:
  pki/dev_private.key  – Developer RSA private key  (keep SECRET on CI/CD)
  pki/dev_cert.pem     – Certificate signed by CA   (submitted with each update)

The developer certificate is:
  ✓ Submitted to /submit along with each update
  ✓ Verified by server and client against the CA certificate
  ✗ Does NOT contain the private key

Usage:
  python generate_dev_cert.py
  python generate_dev_cert.py --cn "Acme Release Bot" --days 365
"""

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

PKI_DIR       = Path(__file__).resolve().parent / "pki"
CA_KEY_PATH   = PKI_DIR / "ca_private.key"
CA_CERT_PATH  = PKI_DIR / "ca_cert.pem"
DEV_KEY_PATH  = PKI_DIR / "dev_private.key"
DEV_CERT_PATH = PKI_DIR / "dev_cert.pem"


def main():
    parser = argparse.ArgumentParser(description="Generate developer signing certificate")
    parser.add_argument("--cn",   default="SecureUpdateLab Developer", help="CommonName")
    parser.add_argument("--org",  default="SecureUpdateLab",           help="Organization")
    parser.add_argument("--days", default=365, type=int,               help="Validity days")
    args = parser.parse_args()

    if not CA_KEY_PATH.exists() or not CA_CERT_PATH.exists():
        print("[!] CA key/cert not found. Run generate_ca.py first.")
        return

    print("[*] Loading CA key and certificate…")
    ca_key  = serialization.load_pem_private_key(CA_KEY_PATH.read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())

    print("[*] Generating developer RSA-3072 private key…")
    dev_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    DEV_KEY_PATH.write_bytes(
        dev_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    print(f"    Saved → {DEV_KEY_PATH}")

    now = datetime.datetime.now(datetime.timezone.utc)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,           "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,      args.org),
        x509.NameAttribute(NameOID.COMMON_NAME,            args.cn),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)    # signed by CA
        .public_key(dev_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=args.days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,    # can sign update files
                content_commitment=True,   # non-repudiation
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,       # CANNOT sign other certs
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(dev_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())    # signed with CA private key
    )

    DEV_CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"    Saved → {DEV_CERT_PATH}")
    print()
    print("[✓] Developer certificate generated.")
    print(f"    Subject : {subject.rfc4514_string()}")
    print(f"    Issuer  : {ca_cert.subject.rfc4514_string()}")
    print(f"    Valid   : {now.date()} → {(now + datetime.timedelta(days=args.days)).date()}")
    print()
    print("[!] Keep dev_private.key SECRET (e.g. in CI/CD secrets, not in git).")


if __name__ == "__main__":
    main()
