from extensions import db
from datetime import datetime


class Role(db.Model):
    """
    Roles: admin, manager, user
    """
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)  # admin | manager | user
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship
    users = db.relationship("User", backref="role", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
        }

    def __repr__(self):
        return f"<Role {self.name}>"


class User(db.Model):
    """
    User model — stores all auth and profile data.
    Passwords are NEVER stored in plain text.
    """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    # ── Password (hashed via bcrypt) ──────────────────
    password_hash = db.Column(db.String(255), nullable=True)  # nullable for OAuth users

    # ── Role ──────────────────────────────────────────
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)

    # ── OAuth ─────────────────────────────────────────
    oauth_provider = db.Column(db.String(50), nullable=True)   # 'github' | 'google' | None
    oauth_id = db.Column(db.String(200), nullable=True)        # provider's user ID

    # ── Two-Factor Authentication ─────────────────────
    totp_secret = db.Column(db.String(64), nullable=True)      # Base32 TOTP secret
    is_2fa_enabled = db.Column(db.Boolean, default=False)

    # ── Account State ─────────────────────────────────
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)

    # ── RSA Key Pair for Digital Signatures ───────────
    private_key_pem = db.Column(db.Text, nullable=True)        # encrypted private key
    public_key_pem = db.Column(db.Text, nullable=True)         # stored openly

    # ── Timestamps ────────────────────────────────────
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    # ── Relationships ──────────────────────────────────
    documents = db.relationship(
        "Document",
        foreign_keys="Document.user_id",
        backref="owner",
        lazy=True,
        cascade="all, delete-orphan"
    )

    def to_dict(self, include_sensitive=False):
        data = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role.name if self.role else None,
            "oauth_provider": self.oauth_provider,
            "is_2fa_enabled": self.is_2fa_enabled,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }
        if include_sensitive:
            data["public_key_pem"] = self.public_key_pem
        return data

    def __repr__(self):
        return f"<User {self.username} ({self.role.name if self.role else 'no-role'})>"
