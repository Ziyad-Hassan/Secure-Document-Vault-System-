import bcrypt
import re
from config import Config


# ─────────────────────────────────────────────
#  Password Hashing  (bcrypt)
# ─────────────────────────────────────────────

def hash_password(plain_password: str) -> str:
    """
    Hash a password using bcrypt (work factor 12).
    Returns a UTF-8 string safe to store in the DB.
    """
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain-text password against a bcrypt hash.
    Returns True if they match, False otherwise.
    Timing-safe comparison is handled internally by bcrypt.
    """
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8")
    )


# ─────────────────────────────────────────────
#  Password Policy Enforcement
# ─────────────────────────────────────────────

def validate_password_policy(password: str) -> tuple[bool, list[str]]:
    """
    Validate a password against the system policy.

    Returns:
        (is_valid: bool, errors: list[str])
    """
    errors = []

    # Minimum length
    if len(password) < Config.PASSWORD_MIN_LENGTH:
        errors.append(f"Password must be at least {Config.PASSWORD_MIN_LENGTH} characters long.")

    # Uppercase letter
    if Config.PASSWORD_REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter (A-Z).")

    # Lowercase letter
    if Config.PASSWORD_REQUIRE_LOWERCASE and not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter (a-z).")

    # Digit
    if Config.PASSWORD_REQUIRE_DIGIT and not re.search(r"\d", password):
        errors.append("Password must contain at least one digit (0-9).")

    # Special character
    if Config.PASSWORD_REQUIRE_SPECIAL and not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\\/]", password):
        errors.append("Password must contain at least one special character (!@#$%^&*...).")

    return (len(errors) == 0, errors)


def get_password_strength(password: str) -> dict:
    """
    Return a strength score and label for frontend feedback.
    Score: 0-100
    """
    score = 0
    checks = {
        "length_8": len(password) >= 8,
        "length_12": len(password) >= 12,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "special": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\\/]", password)),
        "no_spaces": " " not in password,
    }

    weights = {
        "length_8": 15,
        "length_12": 15,
        "uppercase": 15,
        "lowercase": 15,
        "digit": 20,
        "special": 20,
    }

    for key, passed in checks.items():
        if passed and key in weights:
            score += weights[key]

    if score < 30:
        label = "Weak"
    elif score < 60:
        label = "Fair"
    elif score < 80:
        label = "Good"
    else:
        label = "Strong"

    return {"score": score, "label": label, "checks": checks}
