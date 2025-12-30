import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.database import AsyncSessionLocal
from app.models.message import Message
from app.models.user import User
from app.core.security import get_current_user

router = APIRouter(prefix="/messages", tags=["messages"])

# Helper to get DB session
async def get_db():
    async with AsyncSessionLocal() as db:
        yield db

@router.get("/history/{contact_id}")
async def get_conversation(contact_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Return all messages between current_user and contact_id, ordered by timestamp"""
    try:
        contact_uuid = uuid.UUID(contact_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid contact ID")
    stmt = select(Message).where(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == contact_uuid)) |
        ((Message.sender_id == contact_uuid) & (Message.recipient_id == current_user.id))
    ).order_by(Message.sent_at)
    result = await db.execute(stmt)
    messages = result.scalars().all()
    # Serialize minimal fields for frontend
    return [
        {
            "id": str(msg.id),
            "sender_id": str(msg.sender_id),
            "recipient_id": str(msg.recipient_id),
            "content": msg.ciphertext.decode('utf-8', errors='ignore'),  # placeholder, actual UI may decrypt
            "type": msg.message_type,
            "timestamp": msg.sent_at.isoformat(),
            "status": msg.status,
        }
        for msg in messages
    ]

@router.get("/offline")
async def get_offline_messages(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Return undelivered (not read) messages for the current user"""
    stmt = select(Message).where(
        (Message.recipient_id == current_user.id) & (Message.status != "read")
    ).order_by(Message.sent_at)
    result = await db.execute(stmt)
    msgs = result.scalars().all()
    return [
        {
            "id": str(m.id),
            "sender_id": str(m.sender_id),
            "content": m.ciphertext.decode('utf-8', errors='ignore'),
            "type": m.message_type,
            "timestamp": m.sent_at.isoformat(),
            "status": m.status,
        }
        for m in msgs
    ]
