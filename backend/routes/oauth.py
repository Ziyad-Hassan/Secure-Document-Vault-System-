import os
from flask import Blueprint, jsonify, redirect, request
from authlib.integrations.flask_client import OAuth
from models.user import User, Role
from extensions import db
from middleware.jwt_auth import generate_access_token, generate_refresh_token
import urllib.parse

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

oauth_bp = Blueprint("oauth", __name__, url_prefix="/api/oauth")
oauth = OAuth()

CALLBACK_URL = "https://localhost:5443/api/oauth/callback"

def init_oauth(app):
    oauth.init_app(app)
    oauth.register(
        name='github',
        client_id=os.getenv("GITHUB_CLIENT_ID"),
        client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        api_base_url='https://api.github.com/',
        client_kwargs={'scope': 'user:email'},
    )

@oauth_bp.route('/login')
def login():
    return oauth.github.authorize_redirect(CALLBACK_URL, prompt='login')
@oauth_bp.route('/callback')
def auth_callback():
    try:
        token = oauth.github.authorize_access_token()   
    except Exception as e:
        print(f"[OAuth ERROR] {e}")                     
        return redirect(f"/?error=OAuth+failed")

    resp = oauth.github.get('user', token=token)
    if not resp.ok:
        return redirect("/?error=Failed+to+fetch+GitHub+profile")

    user_info = resp.json()
    username  = user_info.get("login")
    email     = user_info.get("email")

    if not email:
        email_resp = oauth.github.get('user/emails', token=token)
        if email_resp.ok:
            for e in email_resp.json():
                if e.get("primary") and e.get("verified"):
                    email = e.get("email")
                    break

    if not email:
        return redirect("/?error=No+verified+email+on+GitHub")

    user = User.query.filter_by(email=email).first()
    if not user:
        base_username = username
        counter = 1
        while User.query.filter_by(username=username).first():
            username = f"{base_username}{counter}"
            counter += 1

        user_role = Role.query.filter_by(name="user").first()
        user = User(
            username=username,
            email=email,
            password_hash=None,
            role_id=user_role.id if user_role else 1,
            oauth_provider="github",
            oauth_id=str(user_info.get("id", "")),
            is_2fa_enabled=False
        )
        db.session.add(user)
        db.session.commit()

    if not user.is_active:
        return redirect("/?error=Account+deactivated")

    access_token  = generate_access_token(user.id, user.username, user.role.name)
    refresh_token = generate_refresh_token(user.id)

    params = urllib.parse.urlencode({
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "username":      user.username,
        "role":          user.role.name,
    })
    return redirect(f"/pages/oauth-callback.html?{params}")