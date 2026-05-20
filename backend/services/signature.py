"""
Digital Signatures & Integrity Verification
============================================
- RSA-2048 key pair generation per user
- SHA-256 hashing of documents
- RSA-SHA256 digital signing
- Signature verification
- Private key encryption with AES (Fernet) using app secret
"""
import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from config import Config


# ─────────────────────────────────────────────
#  Fernet instance for encrypting private keys
# ─────────────────────────────────────────────
_fernet = Fernet(Config.ENCRYPTION_KEY)


def generate_rsa_keypair() -> tuple[str, str]:
    """
    Generate a fresh RSA-2048 key pair.
    Returns: (private_key_pem: str, public_key_pem: str)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    return private_pem, public_pem


def encrypt_private_key(private_pem: str) -> str:
    """Encrypt a PEM private key string using Fernet (AES-128 + HMAC)."""
    encrypted = _fernet.encrypt(private_pem.encode("utf-8"))
    return encrypted.decode("utf-8")


def decrypt_private_key(encrypted_pem: str) -> str:
    """Decrypt a Fernet-encrypted private key."""
    decrypted = _fernet.decrypt(encrypted_pem.encode("utf-8"))
    return decrypted.decode("utf-8")


def compute_sha256(file_bytes: bytes) -> str:
    """
    Compute SHA-256 hash of raw file bytes.
    Returns: hex string (64 chars)
    """
    return hashlib.sha256(file_bytes).hexdigest()


def sign_document(file_bytes: bytes, encrypted_private_pem: str) -> str:
    """
    Sign the SHA-256 hash of a document using the user's RSA private key.

    Steps:
        1. Decrypt the private key
        2. Sign the raw bytes with RSA-PSS + SHA-256
        3. Return base64-encoded signature

    Returns: base64-encoded signature string
    """
    private_pem = decrypt_private_key(encrypted_private_pem)
    private_key = serialization.load_pem_private_key(
        private_pem.encode("utf-8"),
        password=None,
        backend=default_backend()
    )

    signature = private_key.sign(
        file_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(file_bytes: bytes, signature_b64: str, public_pem: str) -> bool:
    """
    Verify an RSA-SHA256 signature against the given file bytes and public key.

    Returns: True if valid, False if tampered or invalid
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_pem.encode("utf-8"),
            backend=default_backend()
        )
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            file_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def verify_integrity(file_bytes: bytes, stored_hash: str) -> bool:
    """
    Verify that a file has not been modified by comparing its
    SHA-256 hash to the stored hash.

    Returns: True if file is intact, False if tampered
    """
    current_hash = compute_sha256(file_bytes)
    return current_hash == stored_hash
