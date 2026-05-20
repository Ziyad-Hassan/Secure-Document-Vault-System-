"""
Secure Document Vault — Flask Application
==========================================
Entry point. Creates the app, registers blueprints, initializes DB.
Run with: python app.py
"""
import os
import sys
from flask import Flask, jsonify, send_from_directory

sys.path.insert(0, os.path.dirname(__file__))

from config import Config
from extensions import db, cors


def create_app() -> Flask:
    app = Flask(__name__, static_folder="../frontend", static_url_path="")
    app.config.from_object(Config)

    # ── Session config (OAuth) ───────────
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'   
    app.config['SESSION_COOKIE_SECURE']   = True    
    app.config['SESSION_COOKIE_HTTPONLY'] = True

    # ── Extensions ─────────────────────────────────────
    db.init_app(app)
    cors.init_app(app, resources={r"/api/*": {"origins": "*"}})

    # ── Ensure upload folder exists ────────────────────
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

    # ── Register Blueprints ────────────────────────────
    from routes.auth     import auth_bp
    from routes.twofa    import twofa_bp
    from routes.oauth    import oauth_bp, init_oauth
    from routes.document import document_bp   

    # ── Init OAuth (register_blueprint) ──────
    init_oauth(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(twofa_bp)
    app.register_blueprint(document_bp)
    app.register_blueprint(oauth_bp)

    # ── Initialize database & seed roles ──────────────
    with app.app_context():
        db.create_all()
        _seed_roles()

    # ── Serve frontend ─────────────────────────────────
    @app.route("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.route("/<path:path>")
    def serve_static(path):
        if os.path.exists(os.path.join(app.static_folder, path)):
            return send_from_directory(app.static_folder, path)
        return send_from_directory(app.static_folder, "index.html")

    # ── Health check ───────────────────────────────────
    @app.route("/api/health")
    def health():
        return jsonify({"status": "ok", "app": "Secure Document Vault"}), 200

    # ── Error handlers ─────────────────────────────────
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Resource not found."}), 404

    @app.errorhandler(413)
    def file_too_large(e):
        return jsonify({"error": f"File too large. Max size: {Config.MAX_CONTENT_LENGTH // (1024*1024)} MB."}), 413

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "Internal server error."}), 500

    return app


def _seed_roles():
    from models.user import Role
    roles = [
        ("admin",   "Full system access: manage users, roles, and documents."),
        ("manager", "Can review and verify uploaded documents."),
        ("user",    "Can upload and manage their own documents."),
    ]
    for name, desc in roles:
        if not Role.query.filter_by(name=name).first():
            db.session.add(Role(name=name, description=desc))
    db.session.commit()


# ─────────────────────────────────────────────
#  Run
# ─────────────────────────────────────────────
if __name__ == "__main__":
    app = create_app()

    use_https = os.path.exists(Config.SSL_CERT) and os.path.exists(Config.SSL_KEY)

    if use_https:
        print("[HTTPS] SSL certificates found — running over HTTPS on port 5443")
        ssl_context = (Config.SSL_CERT, Config.SSL_KEY)
        app.run(host="0.0.0.0", port=5443, ssl_context=ssl_context, debug=Config.DEBUG)
    else:
        print("[HTTP]  No SSL certificates found — running over HTTP on port 5000")
        app.run(host="0.0.0.0", port=5000, debug=Config.DEBUG)