import jwt
import functools
from datetime import datetime, timedelta, timezone
from flask import request, jsonify, g
from config import Config
from extensions import db


# ─────────────────────────────────────────────
#  Token Generation
# ─────────────────────────────────────────────

def generate_access_token(user_id: int, username: str, role: str) -> str:
    """Generate a short-lived JWT access token (default: 60 min)."""
    payload = {
        "sub": user_id,           # subject (user ID)
        "username": username,
        "role": role,
        "type": "access",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=Config.JWT_ACCESS_EXPIRES_MINUTES),
    }
    return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm="HS256")


def generate_refresh_token(user_id: int) -> str:
    """Generate a long-lived JWT refresh token (default: 7 days)."""
    payload = {
        "sub": user_id,
        "type": "refresh",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(days=Config.JWT_REFRESH_EXPIRES_DAYS),
    }
    return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm="HS256")


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token. Raises jwt.ExpiredSignatureError or jwt.InvalidTokenError."""
    return jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=["HS256"])


# ─────────────────────────────────────────────
#  JWT Required Decorator
# ─────────────────────────────────────────────

def jwt_required(f):
    """
    Decorator that protects a route with JWT authentication.
    Reads the token from:  Authorization: Bearer <token>
    Sets g.current_user_id, g.current_username, g.current_role
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization header missing or malformed."}), 401

        token = auth_header.split(" ", 1)[1]
        try:
            payload = decode_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired. Please log in again."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token."}), 401

        if payload.get("type") != "access":
            return jsonify({"error": "Invalid token type."}), 401

        # Store in Flask's g for use in route handlers
        g.current_user_id = payload["sub"]
        g.current_username = payload["username"]
        g.current_role = payload["role"]

        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────
#  Role-Based Access Control Decorator
# ─────────────────────────────────────────────

def role_required(*allowed_roles):
    """
    Decorator that restricts access to specific roles.
    Must be used AFTER @jwt_required.

    Usage:
        @jwt_required
        @role_required("admin")
        def admin_only_route(): ...

        @jwt_required
        @role_required("admin", "manager")
        def admin_or_manager_route(): ...
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, "current_role"):
                return jsonify({"error": "Authentication required."}), 401

            if g.current_role not in allowed_roles:
                return jsonify({
                    "error": f"Access denied. Required role(s): {', '.join(allowed_roles)}. "
                             f"Your role: {g.current_role}"
                }), 403

            return f(*args, **kwargs)
        return decorated
    return decorator
