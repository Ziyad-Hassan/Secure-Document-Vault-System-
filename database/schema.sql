-- ================================================
-- Secure Document Vault — Database Schema
-- Engine: SQLite (development) / PostgreSQL (prod)
-- Generated automatically by SQLAlchemy ORM
-- ================================================

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        VARCHAR(50)  UNIQUE NOT NULL,  -- 'admin' | 'manager' | 'user'
    description VARCHAR(200),
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Seed default roles
INSERT OR IGNORE INTO roles (name, description) VALUES
  ('admin',   'Full system access: manage users, roles, and documents.'),
  ('manager', 'Can review and verify uploaded documents.'),
  ('user',    'Can upload and manage their own documents.');

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         VARCHAR(80)  UNIQUE NOT NULL,
    email            VARCHAR(120) UNIQUE NOT NULL,
    password_hash    VARCHAR(255),               -- bcrypt hash (NULL for OAuth users)
    role_id          INTEGER NOT NULL REFERENCES roles(id),
    oauth_provider   VARCHAR(50),                -- 'github' | 'google' | NULL
    oauth_id         VARCHAR(200),               -- provider user ID
    totp_secret      VARCHAR(64),                -- Base32 TOTP secret (for 2FA)
    is_2fa_enabled   BOOLEAN DEFAULT 0,
    is_active        BOOLEAN DEFAULT 1,
    is_verified      BOOLEAN DEFAULT 0,
    private_key_pem  TEXT,                       -- AES-encrypted RSA private key
    public_key_pem   TEXT,                       -- RSA public key (plain)
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login       DATETIME
);

-- Documents table
CREATE TABLE IF NOT EXISTS documents (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_filename   VARCHAR(255) NOT NULL,   -- shown to user
    stored_filename     VARCHAR(255) NOT NULL,   -- UUID on disk (encrypted)
    file_size           INTEGER NOT NULL,        -- bytes (original)
    file_type           VARCHAR(50)  NOT NULL,   -- MIME type
    file_extension      VARCHAR(20)  NOT NULL,   -- .pdf, .docx ...
    is_encrypted        BOOLEAN DEFAULT 1,       -- always true in this system
    sha256_hash         VARCHAR(64)  NOT NULL,   -- SHA-256 of ORIGINAL file
    digital_signature   TEXT,                   -- RSA-SHA256 signature (base64)
    signature_algorithm VARCHAR(50)  DEFAULT 'RSA-SHA256',
    is_verified         BOOLEAN DEFAULT 0,       -- verified by manager/admin
    verified_by         INTEGER REFERENCES users(id),
    verified_at         DATETIME,
    description         VARCHAR(500),
    uploaded_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_docs_user      ON documents(user_id);
CREATE INDEX IF NOT EXISTS idx_docs_hash      ON documents(sha256_hash);
