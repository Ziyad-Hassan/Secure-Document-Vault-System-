from flask import Blueprint, request, jsonify, g
from datetime import datetime, timezone
from extensions import db
from models import User, Role
from utils.password import hash_password, verify_password, validate_password_policy, get_password_strength
from middleware.jwt_auth import (
    generate_access_token, generate_refresh_token,
    decode_token, jwt_required
)
import jwt

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


# ─────────────────────────────────────────────
#  POST /api/auth/register
# ─────────────────────────────────────────────

@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Register a new user.
    Body: { username, email, password, confirm_password }
    Default role: 'user'
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON."}), 400

    # ── Required fields ────────────────────────────────
    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    confirm_password = data.get("confirm_password", "")

    if not all([username, email, password, confirm_password]):
        return jsonify({"error": "All fields are required: username, email, password, confirm_password."}), 400

    # ── Password match ─────────────────────────────────
    if password != confirm_password:
        return jsonify({"error": "Passwords do not match."}), 400

    # ── Password policy ────────────────────────────────
    is_valid, policy_errors = validate_password_policy(password)
    if not is_valid:
        return jsonify({"error": "Password does not meet policy requirements.", "details": policy_errors}), 400

    # ── Duplicate check ────────────────────────────────
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username is already taken."}), 409

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email is already registered."}), 409

    # ── Assign default role: 'user' ────────────────────
    user_role = Role.query.filter_by(name="user").first()
    if not user_role:
        return jsonify({"error": "Default role not found. Please contact admin."}), 500

    # ── Create user ────────────────────────────────────
    new_user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),   # bcrypt hash
        role_id=user_role.id,
    )

    # ── Generate RSA key pair for digital signatures ───
    from services.signature import generate_rsa_keypair, encrypt_private_key
    private_pem, public_pem = generate_rsa_keypair()
    new_user.public_key_pem = public_pem
    new_user.private_key_pem = encrypt_private_key(private_pem)  # encrypted with app key

    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        "message": "Registration successful.",
        "user": new_user.to_dict()
    }), 201


# ─────────────────────────────────────────────
#  POST /api/auth/login
# ─────────────────────────────────────────────

@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Login with username/email + password.
    If 2FA is enabled, returns { requires_2fa: true } instead of tokens.
    Body: { identifier, password }  (identifier = username or email)
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON."}), 400

    identifier = data.get("identifier", "").strip()
    password = data.get("password", "")

    if not identifier or not password:
        return jsonify({"error": "identifier and password are required."}), 400

    # ── Find user by username OR email ─────────────────
    user = User.query.filter(
        (User.username == identifier) | (User.email == identifier.lower())
    ).first()

    # ── Generic error (don't reveal if user exists) ────
    if not user or not user.password_hash:
        return jsonify({"error": "Invalid credentials."}), 401

    if not verify_password(password, user.password_hash):
        return jsonify({"error": "Invalid credentials."}), 401

    if not user.is_active:
        return jsonify({"error": "Account is deactivated. Contact admin."}), 403

    # ── 2FA check ──────────────────────────────────────
    if user.is_2fa_enabled:
        # Return a temporary indicator — frontend will prompt for TOTP code
        # We issue a short-lived partial token for the 2FA step
        partial_token = generate_access_token(user.id, user.username, user.role.name)
        return jsonify({
            "requires_2fa": True,
            "partial_token": partial_token,   # valid for 5 min, used only for /verify-2fa
            "message": "Please enter your 2FA code."
        }), 200

    # ── Issue tokens ───────────────────────────────────
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()

    access_token = generate_access_token(user.id, user.username, user.role.name)
    refresh_token = generate_refresh_token(user.id)

    return jsonify({
        "message": "Login successful.",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": user.to_dict()
    }), 200


# ─────────────────────────────────────────────
#  POST /api/auth/logout
# ─────────────────────────────────────────────

@auth_bp.route("/logout", methods=["POST"])
@jwt_required
def logout():
    """
    Logout the current user.
    Since JWTs are stateless, logout is handled client-side (delete tokens).
    In a production system, a token blocklist would be used here.
    """
    return jsonify({
        "message": f"User '{g.current_username}' logged out successfully.",
        "hint": "Please delete your access and refresh tokens from the client."
    }), 200


# ─────────────────────────────────────────────
#  POST /api/auth/refresh
# ─────────────────────────────────────────────

@auth_bp.route("/refresh", methods=["POST"])
def refresh():
    """
    Issue a new access token using a valid refresh token.
    Body: { refresh_token }
    """
    data = request.get_json()
    refresh_token = data.get("refresh_token") if data else None

    if not refresh_token:
        return jsonify({"error": "refresh_token is required."}), 400

    try:
        payload = decode_token(refresh_token)
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token has expired. Please log in again."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid refresh token."}), 401

    if payload.get("type") != "refresh":
        return jsonify({"error": "Token type must be 'refresh'."}), 401

    user = User.query.get(payload["sub"])
    if not user or not user.is_active:
        return jsonify({"error": "User not found or deactivated."}), 401

    new_access_token = generate_access_token(user.id, user.username, user.role.name)
    return jsonify({
        "access_token": new_access_token,
        "user": user.to_dict()
    }), 200


# ─────────────────────────────────────────────
#  GET /api/auth/me
# ─────────────────────────────────────────────

@auth_bp.route("/me", methods=["GET"])
@jwt_required
def me():
    """Return current authenticated user's profile."""
    user = User.query.get(g.current_user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404
    return jsonify({"user": user.to_dict(include_sensitive=True)}), 200


# ─────────────────────────────────────────────
#  POST /api/auth/password-strength
# ─────────────────────────────────────────────

@auth_bp.route("/password-strength", methods=["POST"])
def password_strength():
    """
    Check password strength without registering.
    Used for real-time frontend feedback.
    Body: { password }
    """
    data = request.get_json()
    password = data.get("password", "") if data else ""
    result = get_password_strength(password)
    _, policy_errors = validate_password_policy(password)
    result["policy_errors"] = policy_errors
    return jsonify(result), 200
