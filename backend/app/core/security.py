from datetime import datetime, timedelta
from typing import Optional
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from passlib.context import CryptContext
from app.core.config import settings

pwd_context = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

import hashlib

import bcrypt

def verify_password(plain_password, hashed_password):
    # Helper for direct bcrypt check
    def check_bcrypt(plain, hashed):
        try:
            if hashed.startswith("$2b$") or hashed.startswith("$2a$") or hashed.startswith("$2y$"):
                # Ensure bytes
                if isinstance(plain, str): plain = plain.encode('utf-8')
                if isinstance(hashed, str): hashed = hashed.encode('utf-8')
                return bcrypt.checkpw(plain, hashed)
        except Exception:
            pass
        return False

    # 1. Try verifying with pre-hashing (New standard)
    # This handles new users who have pbkdf2_sha256(sha256(password))
    try:
        password_hash = hashlib.sha256(plain_password.encode()).hexdigest()
        if pwd_context.verify(password_hash, hashed_password):
            return True
    except Exception:
        pass # Fallthrough

    # 2. If failed, try verifying raw password (Legacy support)
    # This handles old users created before the pre-hashing fix
    
    # OPTIMIZATION: Check if it's a bcrypt hash and use direct check to avoid passlib error
    if hashed_password.startswith("$2b$") or hashed_password.startswith("$2a$") or hashed_password.startswith("$2y$"):
        if check_bcrypt(plain_password, hashed_password):
            return True
    else:
        # For non-bcrypt hashes (e.g. old pbkdf2), use passlib
        try:
            if pwd_context.verify(plain_password, hashed_password):
                return True
        except Exception:
            pass

    return False

def get_password_hash(password):
    print(f"DEBUG: get_password_hash called with type {type(password)}")
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    print(f"DEBUG: Pre-hashed password: {password_hash} (len: {len(password_hash)})")
    return pwd_context.hash(password_hash)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt
