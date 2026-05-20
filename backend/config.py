import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import base64

load_dotenv()

class Config:
    # ── Flask ──────────────────────────────────────────
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-prod")
    DEBUG = os.getenv("FLASK_ENV") == "development"

    # ── Database ───────────────────────────────────────
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///secure_vault.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── JWT ────────────────────────────────────────────
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "jwt-secret-change-in-prod")
    JWT_ACCESS_EXPIRES_MINUTES = int(os.getenv("JWT_ACCESS_EXPIRES_MINUTES", 60))
    JWT_REFRESH_EXPIRES_DAYS = int(os.getenv("JWT_REFRESH_EXPIRES_DAYS", 7))

    # ── File Uploads ───────────────────────────────────
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_FILE_SIZE_MB", 10)) * 1024 * 1024  # bytes
    ALLOWED_EXTENSIONS = set(
        os.getenv("ALLOWED_EXTENSIONS", "pdf,docx,txt,png,jpg,jpeg").split(",")
    )

    # ── AES-256 Encryption Key ─────────────────────────
    # If not set in .env, generate one and SAVE IT (losing it = losing all files)
    _enc_key = os.getenv("ENCRYPTION_KEY")
    if _enc_key:
        ENCRYPTION_KEY = _enc_key.encode() if isinstance(_enc_key, str) else _enc_key
    else:
        # Generate and store a new key
        ENCRYPTION_KEY = Fernet.generate_key()
        print(f"[WARNING] No ENCRYPTION_KEY found. Generated: {ENCRYPTION_KEY.decode()}")
        print("[WARNING] Add this to your .env file or you will lose access to encrypted files!")

    # ── OAuth ──────────────────────────────────────────
    GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
    GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

    # ── 2FA ────────────────────────────────────────────
    TOTP_ISSUER = os.getenv("TOTP_ISSUER", "SecureDocumentVault")

    # ── HTTPS ──────────────────────────────────────────
    SSL_CERT = os.getenv("SSL_CERT_PATH", "../certs/cert.pem")
    SSL_KEY = os.getenv("SSL_KEY_PATH", "../certs/key.pem")

    # ── Password Policy ────────────────────────────────
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGIT = True
    PASSWORD_REQUIRE_SPECIAL = True
