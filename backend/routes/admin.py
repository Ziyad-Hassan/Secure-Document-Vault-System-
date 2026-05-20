"""
Admin Panel Routes
==================
GET    /api/admin/users              → List all users
GET    /api/admin/users/<id>         → Get user details
PATCH  /api/admin/users/<id>/role    → Change user role
PATCH  /api/admin/users/<id>/toggle  → Activate / deactivate user
DELETE /api/admin/users/<id>         → Delete user
GET    /api/admin/stats              → System statistics
GET    /api/admin/documents          → All documents
"""
from flask import Blueprint, request, jsonify, g
from extensions import db
from models import User, Role, Document
from middleware.jwt_auth import jwt_required, role_required

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


# ── Auth guard: all admin routes require admin role ───

@admin_bp.before_request
def require_admin():
    pass   # enforced per-route with @role_required


# ─────────────────────────────────────────────
#  GET /api/admin/stats
# ─────────────────────────────────────────────

@admin_bp.route("/stats", methods=["GET"])
@jwt_required
@role_required("admin", "manager")
def stats():
    """System-wide statistics dashboard."""
    total_users     = User.query.count()
    active_users    = User.query.filter_by(is_active=True).count()
    total_docs      = Document.query.count()
    verified_docs   = Document.query.filter_by(is_verified=True).count()
    encrypted_docs  = Document.query.filter_by(is_encrypted=True).count()
    users_with_2fa  = User.query.filter_by(is_2fa_enabled=True).count()

    # Role breakdown
    roles = Role.query.all()
    role_counts = {}
    for role in roles:
        role_counts[role.name] = User.query.filter_by(role_id=role.id).count()

    # Total storage (encrypted bytes on disk)
    import os
    from config import Config
    total_size = 0
    if os.path.exists(Config.UPLOAD_FOLDER):
        for f in os.listdir(Config.UPLOAD_FOLDER):
            fp = os.path.join(Config.UPLOAD_FOLDER, f)
            if os.path.isfile(fp):
                total_size += os.path.getsize(fp)

    return jsonify({
        "users": {
            "total": total_users,
            "active": active_users,
            "with_2fa": users_with_2fa,
            "by_role": role_counts,
        },
        "documents": {
            "total": total_docs,
            "verified": verified_docs,
            "encrypted": encrypted_docs,
        },
        "storage": {
            "total_bytes": total_size,
            "total_readable": _readable(total_size),
        }
    }), 200


# ─────────────────────────────────────────────
#  GET /api/admin/users
# ─────────────────────────────────────────────

@admin_bp.route("/users", methods=["GET"])
@jwt_required
@role_required("admin")
def list_users():
    """List all users with their roles and document counts."""
    users = User.query.order_by(User.created_at.desc()).all()
    result = []
    for u in users:
        d = u.to_dict()
        d["document_count"] = Document.query.filter_by(user_id=u.id).count()
        result.append(d)
    return jsonify({"users": result, "total": len(result)}), 200


# ─────────────────────────────────────────────
#  GET /api/admin/users/<id>
# ─────────────────────────────────────────────

@admin_bp.route("/users/<int:user_id>", methods=["GET"])
@jwt_required
@role_required("admin")
def get_user(user_id):
    """Get full user details including document list."""
    user = User.query.get_or_404(user_id)
    data = user.to_dict(include_sensitive=True)
    data["documents"] = [d.to_dict() for d in user.documents]
    return jsonify({"user": data}), 200


# ─────────────────────────────────────────────
#  PATCH /api/admin/users/<id>/role
# ─────────────────────────────────────────────

@admin_bp.route("/users/<int:user_id>/role", methods=["PATCH"])
@jwt_required
@role_required("admin")
def change_role(user_id):
    """
    Change a user's role.
    Body: { role: "admin" | "manager" | "user" }
    Admins cannot demote themselves.
    """
    if user_id == g.current_user_id:
        return jsonify({"error": "You cannot change your own role."}), 400

    data = request.get_json()
    new_role_name = data.get("role", "").strip().lower() if data else ""

    role = Role.query.filter_by(name=new_role_name).first()
    if not role:
        return jsonify({"error": f"Role '{new_role_name}' not found. Valid: admin, manager, user"}), 400

    user = User.query.get_or_404(user_id)
    old_role = user.role.name
    user.role_id = role.id
    db.session.commit()

    return jsonify({
        "message": f"User '{user.username}' role changed: {old_role} → {new_role_name}",
        "user": user.to_dict()
    }), 200


# ─────────────────────────────────────────────
#  PATCH /api/admin/users/<id>/toggle
# ─────────────────────────────────────────────

@admin_bp.route("/users/<int:user_id>/toggle", methods=["PATCH"])
@jwt_required
@role_required("admin")
def toggle_user(user_id):
    """Activate or deactivate a user account."""
    if user_id == g.current_user_id:
        return jsonify({"error": "You cannot deactivate your own account."}), 400

    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()

    status = "activated" if user.is_active else "deactivated"
    return jsonify({
        "message": f"User '{user.username}' has been {status}.",
        "is_active": user.is_active
    }), 200


# ─────────────────────────────────────────────
#  DELETE /api/admin/users/<id>
# ─────────────────────────────────────────────

@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
@jwt_required
@role_required("admin")
def delete_user(user_id):
    """
    Delete a user and all their documents (cascade).
    Files on disk are also removed.
    """
    if user_id == g.current_user_id:
        return jsonify({"error": "You cannot delete your own account."}), 400

    user = User.query.get_or_404(user_id)

    # Remove encrypted files from disk
    import os
    from config import Config
    for doc in user.documents:
        fp = os.path.join(Config.UPLOAD_FOLDER, doc.stored_filename)
        if os.path.exists(fp):
            os.remove(fp)

    username = user.username
    db.session.delete(user)   # cascade deletes documents too
    db.session.commit()

    return jsonify({"message": f"User '{username}' and all their data have been deleted."}), 200


# ─────────────────────────────────────────────
#  GET /api/admin/documents
# ─────────────────────────────────────────────

@admin_bp.route("/documents", methods=["GET"])
@jwt_required
@role_required("admin", "manager")
def list_all_documents():
    """List all documents across all users."""
    docs = Document.query.order_by(Document.uploaded_at.desc()).all()
    return jsonify({
        "documents": [d.to_dict() for d in docs],
        "total": len(docs)
    }), 200


# ─────────────────────────────────────────────
#  GET /api/admin/roles
# ─────────────────────────────────────────────

@admin_bp.route("/roles", methods=["GET"])
@jwt_required
@role_required("admin")
def list_roles():
    roles = Role.query.all()
    return jsonify({"roles": [r.to_dict() for r in roles]}), 200


# ── Helper ────────────────────────────────────

def _readable(size):
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
