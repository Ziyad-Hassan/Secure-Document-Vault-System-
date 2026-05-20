from extensions import db

from datetime import datetime





class Document(db.Model):

    """

    Represents an uploaded document.

    - File is stored encrypted on disk (AES-256)

    - SHA-256 hash is stored for integrity verification

    - RSA digital signature is stored

    """

    __tablename__ = "documents"



    id = db.Column(db.Integer, primary_key=True)



    # ── Ownership ──────────────────────────────────────

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)



    # ── File Metadata ──────────────────────────────────

    original_filename = db.Column(db.String(255), nullable=False)  # original name shown to user

    stored_filename = db.Column(db.String(255), nullable=False)    # UUID-based name on disk

    file_size = db.Column(db.Integer, nullable=False)              # bytes (original size)

    file_type = db.Column(db.String(50), nullable=False)           # MIME type

    file_extension = db.Column(db.String(20), nullable=False)      # e.g. .pdf



    # ── Encryption (AES-256 via Fernet) ───────────────

    is_encrypted = db.Column(db.Boolean, default=True)



    # ── Integrity & Signature ─────────────────────────

    sha256_hash = db.Column(db.String(64), nullable=False)         # SHA-256 of ORIGINAL file

    digital_signature = db.Column(db.Text, nullable=True)          # RSA signature (base64)

    signature_algorithm = db.Column(db.String(50), default="RSA-SHA256")



    # ── Status ────────────────────────────────────────

    is_verified = db.Column(db.Boolean, default=False)             # Manager verified

    verified_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    verified_at = db.Column(db.DateTime, nullable=True)



    # ── Timestamps ────────────────────────────────────

    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)



    # ── Description ───────────────────────────────────

    description = db.Column(db.String(500), nullable=True)



    def to_dict(self):

        return {

            "id": self.id,

            "original_filename": self.original_filename,

            "file_size": self.file_size,

            "file_size_readable": self._readable_size(),

            "file_type": self.file_type,

            "file_extension": self.file_extension,

            "is_encrypted": self.is_encrypted,

            "sha256_hash": self.sha256_hash,

            "has_signature": bool(self.digital_signature),

            "signature_algorithm": self.signature_algorithm,

            "is_verified": self.is_verified,

            "description": self.description,

            "uploaded_at": self.uploaded_at.isoformat(),

            "owner": self.owner.username if self.owner else None,

        }



    def _readable_size(self):

        """Convert bytes to human-readable size."""

        size = self.file_size

        for unit in ["B", "KB", "MB", "GB"]:

            if size < 1024:

                return f"{size:.1f} {unit}"

            size /= 1024

        return f"{size:.1f} TB"



    def __repr__(self):

        return f"<Document {self.original_filename} (user_id={self.user_id})>"