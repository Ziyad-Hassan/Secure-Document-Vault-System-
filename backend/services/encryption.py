"""
Document Encryption Service (AES-256)
=======================================
Uses Python's `cryptography` library with Fernet symmetric encryption.
Fernet is built on AES-128-CBC + HMAC-SHA256 under the hood.
For true AES-256, we use AES-GCM directly.

Documents are encrypted BEFORE being written to disk.
They are decrypted ONLY when a user downloads them.
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from config import Config


def _get_aes_key() -> bytes:
    """
    Derive a 32-byte (256-bit) AES key from the configured ENCRYPTION_KEY.
    If the key is already 32 bytes, use it directly.
    Otherwise, SHA-256 hash it to get exactly 32 bytes.
    """
    raw = Config.ENCRYPTION_KEY
    if isinstance(raw, str):
        raw = raw.encode()

    # Fernet keys are 44 chars (base64-encoded 32 bytes); decode if needed
    try:
        decoded = base64.urlsafe_b64decode(raw)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass

    # Fall back: SHA-256 hash to get 32 bytes
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(raw)
    return digest.finalize()


def encrypt_file(plaintext_bytes: bytes) -> bytes:
    """
    Encrypt raw file bytes using AES-256-GCM.

    Format of output:
        [12-byte nonce][ciphertext + 16-byte GCM auth tag]

    The nonce is randomly generated per file, prepended to the ciphertext.
    """
    key = _get_aes_key()
    nonce = os.urandom(12)          # 96-bit nonce for GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return nonce + ciphertext       # prepend nonce for storage


def decrypt_file(encrypted_bytes: bytes) -> bytes:
    """
    Decrypt AES-256-GCM encrypted bytes.

    Expects format: [12-byte nonce][ciphertext + auth tag]
    Raises ValueError if authentication fails (file has been tampered).
    """
    key = _get_aes_key()
    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError(f"Decryption failed — file may be corrupted or tampered: {e}")


def encrypt_and_save(plaintext_bytes: bytes, save_path: str) -> None:
    """Encrypt file bytes and write encrypted content to disk."""
    encrypted = encrypt_file(plaintext_bytes)
    with open(save_path, "wb") as f:
        f.write(encrypted)


def load_and_decrypt(file_path: str) -> bytes:
    """Read encrypted file from disk and return decrypted bytes."""
    with open(file_path, "rb") as f:
        encrypted = f.read()
    return decrypt_file(encrypted)
