from sqlalchemy import Column, String, DateTime, LargeBinary, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid
from app.database import Base

class Message(Base):
    __tablename__ = "messages"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sender_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    recipient_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    # Encryption Metadata
    nonce = Column(LargeBinary, nullable=False)
    ciphertext = Column(LargeBinary, nullable=False)
    auth_tag = Column(LargeBinary, nullable=False)
    aad = Column(Text, nullable=True)
    hybrid_session_id = Column(UUID(as_uuid=True), nullable=True) # Link to the key used
    
    # Message Metadata
    message_type = Column(String, default="text") # text, photo, file
    file_url = Column(String, nullable=True)
    file_name = Column(String, nullable=True)
    file_size = Column(Integer, nullable=True)
    
    status = Column(String, default="sent") # sent, delivered, read
    sent_at = Column(DateTime(timezone=True), server_default=func.now())
    read_at = Column(DateTime(timezone=True), nullable=True)
