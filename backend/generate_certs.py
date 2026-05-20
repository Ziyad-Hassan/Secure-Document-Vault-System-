"""
Generate Self-Signed SSL Certificate for HTTPS
================================================
Run this ONCE before starting the server with HTTPS.
Output: ../certs/cert.pem  and  ../certs/key.pem
"""
import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

CERTS_DIR = os.path.join(os.path.dirname(__file__), "..", "certs")
CERT_FILE = os.path.join(CERTS_DIR, "cert.pem")
KEY_FILE  = os.path.join(CERTS_DIR, "key.pem")


def generate_self_signed_cert():
    os.makedirs(CERTS_DIR, exist_ok=True)

    # ── Generate private key ───────────────────────────
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # ── Build certificate ──────────────────────────────
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Development"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Document Vault"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # ── Write files ────────────────────────────────────
    with open(KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[OK] Certificate: {CERT_FILE}")
    print(f"[OK] Private key: {KEY_FILE}")
    print("[NOTE] This is a self-signed certificate for development only.")
    print("[NOTE] Browsers will show a security warning — that is expected.")
    print("[NOTE] For production, use a real certificate from Let's Encrypt.")


if __name__ == "__main__":
    generate_self_signed_cert()
