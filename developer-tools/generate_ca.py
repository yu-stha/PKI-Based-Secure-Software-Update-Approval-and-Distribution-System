"""
generate_ca.py – Generate Root CA Key and Self-Signed Certificate
=================================================================
Run this ONCE to establish the PKI root of trust.

Output files:
  pki/ca_private.key  – RSA 4096 private key (keep SECRET, offline ideally)
  pki/ca_cert.pem     – Self-signed CA certificate (distribute to clients)

The CA certificate must be:
  ✓ Copied to update-server/pki/ca_cert.pem
  ✓ Copied to client-app/ca_cert.pem
  ✗ NEVER distribute the private key

NIST SP 800-57: Use RSA ≥ 2048 bits; we use 4096 for the CA.
"""

from pathlib import Path
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PKI_DIR = Path(__file__).resolve().parent / "pki"
PKI_DIR.mkdir(parents=True, exist_ok=True)

KEY_PATH  = PKI_DIR / "ca_private.key"
CERT_PATH = PKI_DIR / "ca_cert.pem"

def main():
    print("[*] Generating CA RSA-4096 private key…")
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    print(f"    Saved → {KEY_PATH}")

    now = datetime.datetime.now(datetime.timezone.utc)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,             "NP"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,   "Bagmati"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "SecureUpdateLab CA"),
        x509.NameAttribute(NameOID.COMMON_NAME,              "SecureUpdateLab Root CA"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)          # self-signed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,     # can sign other certs
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"    Saved → {CERT_PATH}")
    print()
    print("[✓] CA generated successfully.")
    print()
    print("Next steps:")
    print(f"  cp {CERT_PATH} ../update-server/pki/ca_cert.pem")
    print(f"  cp {CERT_PATH} ../client-app/ca_cert.pem")
    print()
    print("[!] Keep ca_private.key SECRET and ideally offline.")


if __name__ == "__main__":
    main()
