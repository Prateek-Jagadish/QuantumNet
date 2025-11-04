-- QuantumNet PostgreSQL schema initialization
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users with profile fields
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    bio TEXT,
    phone TEXT,
    profile_photo_path TEXT,
    failed_attempts INTEGER DEFAULT 0,
    lockout_until TIMESTAMP,
    photo_hash TEXT,
    totp_secret TEXT,
    email_verified BOOLEAN DEFAULT FALSE,
    email_verification_token TEXT,
    reset_token TEXT,
    reset_expires TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_online BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE
);

-- Messages (support replies, deletions, reactions JSON)
CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    content TEXT NOT NULL,
    encrypted_content TEXT,
    iv TEXT,
    encryption_used BOOLEAN DEFAULT FALSE,
    status TEXT DEFAULT 'pending',
    delivered_at TIMESTAMP,
    read_at TIMESTAMP,
    reply_to INTEGER REFERENCES messages(id),
    is_deleted_sender BOOLEAN DEFAULT FALSE,
    is_deleted_recipient BOOLEAN DEFAULT FALSE,
    reactions JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Contacts with status (normal, favorite, blocked)
CREATE TABLE IF NOT EXISTS contacts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    contact_id INTEGER NOT NULL REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'normal',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, contact_id)
);

-- Devices
CREATE TABLE IF NOT EXISTS devices (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    device_id TEXT NOT NULL,
    device_name TEXT,
    browser TEXT,
    os TEXT,
    ip_address TEXT,
    last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Sessions
CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    session_id TEXT UNIQUE NOT NULL,
    key_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- File shares
CREATE TABLE IF NOT EXISTS file_shares (
    id SERIAL PRIMARY KEY,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    file_name TEXT NOT NULL,
    file_type TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    encrypted_content BYTEA NOT NULL,
    encryption_used BOOLEAN DEFAULT FALSE,
    thumbnail_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Security events
CREATE TABLE IF NOT EXISTS security_events (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    event_type TEXT NOT NULL,
    description TEXT,
    threat_level TEXT DEFAULT 'LOW',
    ml_prediction TEXT,
    confidence REAL,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_messages_recipient_created ON messages(recipient_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_sender_created ON messages(sender_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_contacts_user ON contacts(user_id);
CREATE INDEX IF NOT EXISTS idx_users_username_email ON users((lower(username)), (lower(email)));


