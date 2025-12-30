from sqlalchemy import Column, String, DateTime, LargeBinary, ForeignKey, Float, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid
from app.database import Base

class HybridSessionKey(Base):
    __tablename__ = "hybrid_session_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_a_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    user_b_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    # Encrypted Components (Encrypted with Master Key)
    bb84_entropy_encrypted = Column(LargeBinary, nullable=False)
    bb84_nonce = Column(LargeBinary, nullable=False)
    
    kyber_ciphertext_encrypted = Column(LargeBinary, nullable=False) # The CT sent to B
    kyber_nonce = Column(LargeBinary, nullable=False)
    
    hybrid_key_encrypted = Column(LargeBinary, nullable=False) # The final derived key
    hybrid_nonce = Column(LargeBinary, nullable=False)
    
    qber = Column(Float, nullable=True)
    is_secure = Column(Boolean, default=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
