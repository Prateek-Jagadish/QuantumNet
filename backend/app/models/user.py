from sqlalchemy import Column, String, DateTime, LargeBinary
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=True)
    profile_picture = Column(String, nullable=True) # URL or Base64
    password_hash = Column(String, nullable=False)
    
    # Kyber Keys (Public is visible, Private is encrypted)
    kyber_public_key = Column(LargeBinary, nullable=False)
    kyber_private_key_encrypted = Column(LargeBinary, nullable=False)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
