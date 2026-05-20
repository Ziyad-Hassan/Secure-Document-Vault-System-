from flask import Blueprint, request, jsonify, g
from extensions import db
from models import User
from middleware.jwt_auth import jwt_required, generate_access_token, generate_refresh_token, decode_token
from services.totp import generate_totp_secret, generate_qr_code_base64, verify_totp
from datetime import datetime, timezone
import jwt

twofa_bp = Blueprint("twofa", __name__, url_prefix="/api/2fa")


# ─────────────────────────────────────────────
#  POST /api/2fa/setup
#  Start 2FA setup — generate secret + QR code
# ─────────────────────────────────────────────

@twofa_bp.route("/setup", methods=["POST"])
@jwt_required
def setup_2fa():
    """
    Initiate 2FA setup for the current user.
    Returns a QR code (base64 PNG) and the raw secret for manual entry.
    """
    user = User.query.get(g.current_user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404

    if user.is_2fa_enabled:
        return jsonify({"error": "2FA is already enabled. Disable it first to reconfigure."}), 400

    # Generate new secret
    secret = generate_totp_secret()
    user.totp_secret = secret          # store temporarily (not activated until verified)
    db.session.commit()

    qr_base64 = generate_qr_code_base64(secret, user.username)

    return jsonify({
        "message": "Scan the QR code with your authenticator app, then verify with /api/2fa/verify-setup.",
        "qr_code": f"data:image/png;base64,{qr_base64}",
        "secret": secret,              # show only for manual entry
        "issuer": "SecureDocumentVault"
    }), 200


# ─────────────────────────────────────────────
#  POST /api/2fa/verify-setup
#  Confirm the TOTP code to ACTIVATE 2FA
# ─────────────────────────────────────────────

@twofa_bp.route("/verify-setup", methods=["POST"])
@jwt_required
def verify_setup():
    """
    Confirm 2FA activation by verifying the user's first TOTP code.
    Body: { code }
    """
    user = User.query.get(g.current_user_id)
    if not user or not user.totp_secret:
        return jsonify({"error": "Start setup at /api/2fa/setup first."}), 400

    data = request.get_json()
    code = data.get("code", "").strip() if data else ""

    if not code:
        return jsonify({"error": "TOTP code is required."}), 400

    if not verify_totp(user.totp_secret, code):
        return jsonify({"error": "Invalid TOTP code. Try again."}), 401

    user.is_2fa_enabled = True
    db.session.commit()

    return jsonify({"message": "2FA has been successfully enabled on your account."}), 200


# ─────────────────────────────────────────────
#  POST /api/2fa/verify-login
#  Verify TOTP code during login flow
# ─────────────────────────────────────────────

@twofa_bp.route("/verify-login", methods=["POST"])
def verify_login():
    """
    Complete login for 2FA-enabled users.
    Body: { partial_token, code }
    Returns full access + refresh tokens if code is valid.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON."}), 400

    partial_token = data.get("partial_token", "")
    code = data.get("code", "").strip()

    if not partial_token or not code:
        return jsonify({"error": "partial_token and code are required."}), 400

    # Validate partial token
    try:
        payload = decode_token(partial_token)
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Session expired. Please log in again."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token."}), 401

    user = User.query.get(payload["sub"])
    if not user or not user.is_active:
        return jsonify({"error": "User not found or deactivated."}), 401

    if not user.is_2fa_enabled or not user.totp_secret:
        return jsonify({"error": "2FA is not enabled for this account."}), 400

    if not verify_totp(user.totp_secret, code):
        return jsonify({"error": "Invalid 2FA code."}), 401

    # Issue full tokens
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
#  DELETE /api/2fa/disable
#  Disable 2FA (requires current TOTP code)
# ─────────────────────────────────────────────

@twofa_bp.route("/disable", methods=["DELETE"])
@jwt_required
def disable_2fa():
    """
    Disable 2FA for the current user.
    Body: { code }  — requires a valid TOTP code to confirm identity
    """
    user = User.query.get(g.current_user_id)
    if not user or not user.is_2fa_enabled:
        return jsonify({"error": "2FA is not enabled on this account."}), 400

    data = request.get_json()
    code = data.get("code", "").strip() if data else ""

    if not verify_totp(user.totp_secret, code):
        return jsonify({"error": "Invalid 2FA code."}), 401

    user.is_2fa_enabled = False
    user.totp_secret = None
    db.session.commit()

    return jsonify({"message": "2FA has been disabled."}), 200
