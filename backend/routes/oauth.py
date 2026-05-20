import os
from flask import Blueprint, url_for, jsonify
from authlib.integrations.flask_client import OAuth
from models.user import User, Role
from extensions import db
from middleware.jwt_auth import generate_access_token, generate_refresh_token

oauth_bp = Blueprint("oauth", __name__, url_prefix="/api/oauth")
oauth = OAuth()

def init_oauth(app):
    oauth.init_app(app)
    oauth.register(
        name='github',
        client_id=os.getenv("GITHUB_CLIENT_ID"),
        client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
        access_token_url='https://github.com/login/oauth/access_token',
        access_token_params=None,
        authorize_url='https://github.com/login/oauth/authorize',
        authorize_params=None,
        api_base_url='https://api.github.com/',
        client_kwargs={'scope': 'user:email'},
    )

@oauth_bp.route('/login')
def login():
    """Redirect route for GitHub OAuth login"""
    redirect_uri = url_for('oauth.auth_callback', _external=True)
    return oauth.github.authorize_redirect(redirect_uri)

@oauth_bp.route('/callback')
def auth_callback():
    """Callback route where GitHub returns with user data upon successful login"""
    try:
        token = oauth.github.authorize_access_token()
    except Exception as e:
        return jsonify({"error": "OAuth authentication failed."}), 400

    # Fetch user profile data
    resp = oauth.github.get('user')
    if not resp.ok:
        return jsonify({"error": "Failed to fetch user info from GitHub."}), 400
    
    user_info = resp.json()
    username = user_info.get("login")
    
    # GitHub emails might be private, so we need a separate request to fetch them
    email = user_info.get("email")
    if not email:
        email_resp = oauth.github.get('user/emails')
        if email_resp.ok:
            emails = email_resp.json()
            # Find the primary and verified email
            for e in emails:
                if e.get("primary") and e.get("verified"):
                    email = e.get("email")
                    break

    if not email:
        return jsonify({"error": "No verified email found on this GitHub account."}), 400

    # Check if the user already exists in the database
    user = User.query.filter_by(email=email).first()

    # If user does not exist, create a new account with default 'user' role
    if not user:
        user_role = Role.query.filter_by(name="user").first()
        user = User(
            username=username,
            email=email,
            password_hash="",  # No password needed for OAuth-created accounts
            role_id=user_role.id if user_role else 1,
            is_2fa_enabled=False 
        )
        db.session.add(user)
        db.session.commit()

    # Generate JWT tokens for the authenticated user
    access_token = generate_access_token(user.id, user.username, user.role.name)
    refresh_token = generate_refresh_token(user.id)

    return jsonify({
        "message": "GitHub OAuth Login Successful",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role.name
        }
    }), 200