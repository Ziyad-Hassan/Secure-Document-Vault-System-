"""
Two-Factor Authentication (2FA) — TOTP
=======================================
Uses Time-based One-Time Passwords (RFC 6238).
Compatible with Google Authenticator, Authy, etc.
"""
import pyotp
import qrcode
import io
import base64
from config import Config


def generate_totp_secret() -> str:
    """Generate a random Base32 TOTP secret for a user."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str) -> str:
    """
    Generate the otpauth:// URI for QR code scanning.
    Format: otpauth://totp/ISSUER:username?secret=SECRET&issuer=ISSUER
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(
        name=username,
        issuer_name=Config.TOTP_ISSUER
    )


def generate_qr_code_base64(secret: str, username: str) -> str:
    """
    Generate a QR code image for the TOTP URI.
    Returns: base64-encoded PNG image string (for embedding in HTML)
    """
    uri = get_totp_uri(secret, username)
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode("utf-8")


def verify_totp(secret: str, code: str) -> bool:
    """
    Verify a 6-digit TOTP code.
    Allows ±1 time window (30s grace period) to account for clock drift.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)