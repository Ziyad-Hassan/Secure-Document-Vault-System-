# 🔐 Secure Document Vault

A full-stack secure document management platform implementing modern authentication, authorization, encryption, digital signatures, and secure communication.

---

## 📋 Features

| Module | Implementation |
|--------|---------------|
| **Authentication** | JWT (access + refresh tokens) |
| **Password Security** | bcrypt (rounds=12) + policy enforcement |
| **OAuth 2.0** | GitHub and Google login |
| **Two-Factor Auth (2FA)** | TOTP (RFC 6238) — Google Authenticator compatible |
| **RBAC** | Admin / Manager / User roles |
| **Document Encryption** | AES-256-GCM |
| **Digital Signatures** | RSA-2048 + SHA-256 (PSS padding) |
| **Integrity Verification** | SHA-256 hash comparison |
| **HTTPS** | Self-signed SSL certificate |

---

## 🗂️ Project Structure

```
secure-vault/
├── backend/
│   ├── app.py                  # Flask app factory
│   ├── config.py               # Configuration
│   ├── extensions.py           # SQLAlchemy, CORS
│   ├── generate_certs.py       # HTTPS cert generator
│   ├── requirements.txt
│   ├── .env                    # Environment variables (copy from .env.example)
│   ├── models/
│   │   ├── user.py             # User + Role models
│   │   └── document.py         # Document model
│   ├── routes/
│   │   ├── auth.py             # Register, Login, Logout, Refresh
│   │   ├── twofa.py            # 2FA setup, verify, disable
│   │   ├── documents.py        # Upload, Download, Delete, Verify
│   │   ├── admin.py            # Admin panel APIs
│   │   └── oauth.py            # GitHub + Google OAuth
│   ├── middleware/
│   │   └── jwt_auth.py         # JWT decorator + RBAC decorator
│   ├── services/
│   │   ├── encryption.py       # AES-256-GCM
│   │   ├── signature.py        # RSA signing + SHA-256
│   │   └── totp.py             # TOTP 2FA
│   └── utils/
│       └── password.py         # bcrypt + password policy
├── frontend/
│   ├── index.html              # Login page
│   ├── css/style.css           # Global stylesheet
│   ├── js/
│   │   ├── utils.js            # Shared utilities
│   │   └── auth.js             # Login/Register logic
│   └── pages/
│       ├── register.html
│       ├── dashboard.html
│       ├── upload.html
│       ├── verify.html
│       └── admin.html
├── certs/
│   ├── cert.pem                # SSL certificate (generated)
│   └── key.pem                 # SSL private key (generated)
└── database/
    └── schema.sql              # DB schema documentation
```

---

## 🚀 How to Run

### 1. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env and set:
# - SECRET_KEY (generate with: python -c "import secrets; print(secrets.token_hex(32))")
# - JWT_SECRET_KEY
# - ENCRYPTION_KEY (generated automatically on first run — copy it to .env!)
# - GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET (for OAuth)
# - GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET (for OAuth)
```

### 3. Generate HTTPS Certificates

```bash
python generate_certs.py
```

### 4. Run the Application

```bash
python app.py
```

- **HTTP:**  http://localhost:5000
- **HTTPS:** https://localhost:5443 (after generating certs)

> ⚠️ For HTTPS with a self-signed cert, your browser will show a security warning. Click "Advanced → Proceed" to continue. This is expected in development.

---

## 🔑 Default Roles

After first run, these roles are seeded automatically:

| Role | Permissions |
|------|------------|
| `admin` | Manage users, roles, all documents |
| `manager` | Review and verify documents |
| `user` | Upload and manage own documents |

To create an admin user, register normally then update the role in the database:
```sql
UPDATE users SET role_id = (SELECT id FROM roles WHERE name='admin') WHERE username='yourusername';
```

---

## 🔒 Security Architecture

### Password Storage
- Hashed with **bcrypt** (cost factor 12)
- **Never** stored in plain text
- Policy: min 8 chars, uppercase, lowercase, digit, special char

### JWT Tokens
- **Access token:** 60 min expiry, HS256
- **Refresh token:** 7 days expiry
- Claims: `sub`, `username`, `role`, `type`, `iat`, `exp`

### Document Encryption (AES-256-GCM)
```
Upload flow:
  [Original file] → SHA-256 hash → RSA sign → AES-256-GCM encrypt → [Store on disk]

Download flow:
  [Encrypted file] → AES-256-GCM decrypt → [Send to user]
```

### Digital Signatures (RSA-2048)
- Each user gets a unique RSA-2048 key pair on registration
- Private key is encrypted with AES (Fernet) before storage
- Documents are signed with **RSA-PSS + SHA-256**
- Signature stored in the database alongside the document

### Two-Factor Authentication (TOTP)
- Implements RFC 6238 (Time-based OTP)
- Compatible with Google Authenticator, Authy, Microsoft Authenticator
- 30-second window with ±1 time slot tolerance

---

## 📡 API Endpoints

### Auth
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/register` | ❌ | Register new user |
| POST | `/api/auth/login` | ❌ | Login (returns JWT) |
| POST | `/api/auth/logout` | ✅ | Logout |
| POST | `/api/auth/refresh` | ❌ | Refresh access token |
| GET  | `/api/auth/me` | ✅ | Current user profile |
| POST | `/api/auth/password-strength` | ❌ | Check password strength |

### 2FA
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/2fa/setup` | ✅ | Generate TOTP secret + QR code |
| POST | `/api/2fa/verify-setup` | ✅ | Confirm and activate 2FA |
| POST | `/api/2fa/verify-login` | ❌ | Complete 2FA login |
| DELETE | `/api/2fa/disable` | ✅ | Disable 2FA |

### Documents (coming in Step 2)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/documents/upload` | ✅ | Upload + encrypt + sign |
| GET  | `/api/documents` | ✅ | List my documents |
| GET  | `/api/documents/{id}` | ✅ | Get document metadata |
| GET  | `/api/documents/{id}/download` | ✅ | Download decrypted |
| DELETE | `/api/documents/{id}` | ✅ | Delete document |
| POST | `/api/documents/{id}/verify` | ✅ | Verify integrity + signature |

---

## 🦈 Wireshark MITM Demo

See `docs/wireshark-demo.md` for step-by-step instructions on:
1. Capturing HTTP traffic showing plaintext credentials
2. Enabling HTTPS
3. Capturing HTTPS traffic showing encrypted data

---

## 🛠️ Technologies

- **Backend:** Python 3.12 + Flask 3.0
- **Database:** SQLite (dev) / PostgreSQL (prod)
- **Auth:** PyJWT, bcrypt, pyotp
- **Crypto:** cryptography (AES-256-GCM, RSA-2048)
- **OAuth:** Authlib
- **Frontend:** Vanilla HTML/CSS/JS
