from fastapi import APIRouter, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.database import get_db
from app.models.user import User
from app.core.security import verify_password, get_password_hash, create_access_token
from app.crypto import kyber
from app.core.config import settings
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import binascii
import os
from jose import JWTError, jwt

# FORCE CRASH TO VERIFY LOADING
# raise RuntimeError("I AM HERE - AUTH.PY IS LOADING")

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Helper to encrypt private keys at rest
def encrypt_private_key(private_key: bytes) -> bytes:
    aesgcm = AESGCM(binascii.unhexlify(settings.MASTER_KEY_HEX))
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, private_key, None)
    return nonce + ciphertext

@router.post("/register")
async def register(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(None),
    db: AsyncSession = Depends(get_db)
):
    # Check if username exists
    result = await db.execute(select(User).where(User.username == username))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Check if email exists
    result = await db.execute(select(User).where(User.email == email))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Generate Kyber Keys
    pk, sk = kyber.generate_keypair()
    
    # Encrypt Private Key
    sk_encrypted = encrypt_private_key(sk)
    
    # Create User
    print(f"DEBUG: Registering user {username} with email {email}")
    
    try:
        new_user = User(
            username=username,
            email=email,
            full_name=full_name,
            password_hash=get_password_hash(password),
            kyber_public_key=pk,
            kyber_private_key_encrypted=sk_encrypted,
            profile_picture=f"https://api.dicebear.com/7.x/initials/svg?seed={username}" # Default avatar
        )
        
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        print(f"DEBUG: User created with ID {new_user.id}")
        
        return {"message": "User created successfully", "user_id": str(new_user.id)}
    except Exception as e:
        print(f"DEBUG: Registration failed: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@router.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    print(f"DEBUG: Login attempt for {form_data.username}")
    # Try to find user by username OR email
    # form_data.username could be email
    result = await db.execute(
        select(User).where(
            (User.username == form_data.username) | (User.email == form_data.username)
        )
    )
    user = result.scalars().first()
    print(f"DEBUG: User found: {user.username if user else 'None'}")
    
    if not user or not verify_password(form_data.password, user.password_hash):
        print("DEBUG: Password verification failed")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    access_token = create_access_token(data={"sub": user.username})
    return {
        "access_token": access_token, 
        "token_type": "bearer", 
        "user_id": str(user.id), 
        "username": user.username,
        "full_name": user.full_name,
        "email": user.email,
        "profile_picture": user.profile_picture
    }

from jose import JWTError, jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalars().first()
    if user is None:
        raise credentials_exception
    return user
