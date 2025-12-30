from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from app.database import get_db
from app.models.key import HybridSessionKey
from app.models.message import Message
from app.models.security_event import SecurityEvent
from datetime import datetime, timedelta

router = APIRouter()

@router.get("/metrics")
async def get_security_metrics(db: AsyncSession = Depends(get_db)):
    # 1. QBER (Latest)
    qber_result = await db.execute(
        select(HybridSessionKey.qber).order_by(desc(HybridSessionKey.created_at)).limit(1)
    )
    latest_qber = qber_result.scalars().first() or 0.0
    
    # 2. Encryption Status
    # Check if we have active keys
    active_keys_result = await db.execute(
        select(HybridSessionKey).where(HybridSessionKey.expires_at > datetime.utcnow())
    )
    active_keys_count = len(active_keys_result.scalars().all())
    
    # 3. Message Count
    msg_count_result = await db.execute(select(Message))
    total_messages = len(msg_count_result.scalars().all())
    
    # 4. Security Score (Mock Calculation)
    # Base 40 (BB84) + 30 (Kyber) + 20 (Low QBER) + 10 (Rotation)
    score = 40 + 30 # We always use BB84+Kyber
    if latest_qber < 0.11:
        score += 20
    if active_keys_count > 0:
        score += 10
        
    return {
        "qber": latest_qber,
        "active_keys": active_keys_count,
        "total_messages": total_messages,
        "security_score": score,
        "bb84_status": "Active",
        "kyber_status": "Active",
        "aes_status": "Active"
    }

@router.get("/keys")
async def get_active_keys(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(HybridSessionKey).order_by(desc(HybridSessionKey.created_at)).limit(10)
    )
    keys = result.scalars().all()
    return [
        {
            "id": str(k.id),
            "created_at": k.created_at,
            "expires_at": k.expires_at,
            "qber": k.qber,
            "is_secure": k.is_secure
        }
        for k in keys
    ]

@router.get("/events")
async def get_security_events(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(20)
    )
    events = result.scalars().all()
    return [
        {
            "id": str(e.id),
            "event_type": e.event_type,
            "severity": e.severity,
            "details": e.details,
            "created_at": e.created_at
        }
        for e in events
    ]
