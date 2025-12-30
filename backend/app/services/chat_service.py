from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import and_, desc
from app.models.user import User
from app.models.message import Message
from app.models.key import HybridSessionKey
from app.crypto import bb84, kyber, hybrid, aes
from app.core.config import settings
from datetime import datetime, timedelta
import os
import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Master Key for encrypting keys at rest
MASTER_KEY = binascii.unhexlify(settings.MASTER_KEY_HEX)

def encrypt_at_rest(data: bytes) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(MASTER_KEY)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce, ciphertext

def decrypt_at_rest(nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(MASTER_KEY)
    return aesgcm.decrypt(nonce, ciphertext, None)

async def get_or_create_session_key(db: AsyncSession, user_a_id, user_b_id):
    # 1. Check for existing valid key
    # We check both directions (A->B or B->A) since the key is symmetric
    result = await db.execute(
        select(HybridSessionKey).where(
            and_(
                ((HybridSessionKey.user_a_id == user_a_id) & (HybridSessionKey.user_b_id == user_b_id)) |
                ((HybridSessionKey.user_a_id == user_b_id) & (HybridSessionKey.user_b_id == user_a_id)),
                HybridSessionKey.expires_at > datetime.utcnow(),
                HybridSessionKey.is_secure == True
            )
        ).order_by(desc(HybridSessionKey.created_at))
    )
    existing_key = result.scalars().first()
    
    if existing_key:
        # Decrypt the hybrid key for use
        hybrid_key = decrypt_at_rest(existing_key.hybrid_nonce, existing_key.hybrid_key_encrypted)
        return existing_key, hybrid_key

    # 2. Generate New Key (Handshake)
    # Fetch User B's Public Key
    result = await db.execute(select(User).where(User.id == user_b_id))
    user_b = result.scalars().first()
    if not user_b:
        raise Exception("User B not found")
        
    # BB84 Layer
    bb84_entropy, qber = bb84.generate_quantum_state()
    if qber > 0.11:
        # In real world, we'd retry or abort. For demo, we log it but maybe allow it if we want to show "Compromised" state.
        # Let's allow it but mark is_secure=False if we want to demonstrate that.
        # But spec says "Reject keys if QBER > 11%".
        # So we retry once, then fail.
        bb84_entropy, qber = bb84.generate_quantum_state()
        if qber > 0.11:
             raise Exception(f"Security Alert: High QBER detected ({qber:.2%}). Key exchange aborted.")

    # Kyber Layer
    # Encapsulate against User B's public key
    kyber_ct, kyber_ss = kyber.encapsulate(user_b.kyber_public_key)
    
    # Hybrid Layer
    hybrid_key = hybrid.derive_hybrid_key(bb84_entropy, kyber_ss)
    
    # 3. Store Keys (Encrypted at Rest)
    bb84_nonce, bb84_enc = encrypt_at_rest(bb84_entropy)
    kyber_nonce, kyber_enc = encrypt_at_rest(kyber_ct) # We store CT just for record, or maybe SS? Spec says "kyber_ciphertext_encrypted".
    # Actually, we usually store the Shared Secret encrypted if we need to re-derive, 
    # but here we store the Final Hybrid Key.
    # The spec says "kyber_ciphertext_encrypted". This implies we store the CT so B can decapsulate?
    # Wait. If we are the Server acting as KDC, we just store the derived key and give it to them?
    # Or we store the components.
    # Let's store the Hybrid Key encrypted.
    
    hk_nonce, hk_enc = encrypt_at_rest(hybrid_key)
    
    new_session = HybridSessionKey(
        user_a_id=user_a_id,
        user_b_id=user_b_id,
        bb84_entropy_encrypted=bb84_enc,
        bb84_nonce=bb84_nonce,
        kyber_ciphertext_encrypted=kyber_enc, # Storing CT encrypted
        kyber_nonce=kyber_nonce,
        # We need a tag for these? encrypt_at_rest returns (nonce, ciphertext+tag). 
        # My model has separate columns for tag? No, I defined 'bb84_tag' in SQL but not in model?
        # Let's check model.
        # Model: bb84_entropy_encrypted, bb84_nonce. (No tag column? I should have checked).
        # AESGCM.encrypt returns ciphertext+tag. So 'bb84_entropy_encrypted' will hold both.
        # That's fine.
        hybrid_key_encrypted=hk_enc,
        hybrid_nonce=hk_nonce,
        qber=qber,
        is_secure=True,
        expires_at=datetime.utcnow() + timedelta(hours=24)
    )
    
    db.add(new_session)
    await db.commit()
    await db.refresh(new_session)
    
    return new_session, hybrid_key

async def send_encrypted_message(db: AsyncSession, sender_id, recipient_id, content: str, msg_type="text", file_meta=None):
    # 1. Get Session Key
    session_record, hybrid_key = await get_or_create_session_key(db, sender_id, recipient_id)
    
    # 2. Encrypt Message
    # AAD = sender_id:recipient_id:timestamp (approx)
    # For simplicity, we'll just use sender:recipient as AAD or None.
    # Spec says: "AAD: sender_id:recipient_id:timestamp"
    aad = f"{sender_id}:{recipient_id}:{datetime.utcnow().isoformat()}".encode()
    
    nonce, ciphertext, auth_tag = aes.encrypt_message(hybrid_key, content.encode(), aad)
    
    # 3. Store Message
    new_msg = Message(
        sender_id=sender_id,
        recipient_id=recipient_id,
        nonce=nonce,
        ciphertext=ciphertext,
        auth_tag=auth_tag,
        aad=aad.decode(),
        hybrid_session_id=session_record.id,
        message_type=msg_type,
        status="sent"
    )
    
    if file_meta:
        new_msg.file_url = file_meta.get("url")
        new_msg.file_name = file_meta.get("name")
        new_msg.file_size = file_meta.get("size")
        
    db.add(new_msg)
    await db.commit()
    await db.refresh(new_msg)
    
    return new_msg

async def decrypt_message_content(db: AsyncSession, message: Message):
    # 1. Get Key
    # We need the key from the session
    result = await db.execute(select(HybridSessionKey).where(HybridSessionKey.id == message.hybrid_session_id))
    session_key = result.scalars().first()
    
    if not session_key:
        return "[Error: Session Key Expired or Missing]"
        
    hybrid_key = decrypt_at_rest(session_key.hybrid_nonce, session_key.hybrid_key_encrypted)
    
    # 2. Decrypt
    try:
        plaintext = aes.decrypt_message(
            hybrid_key, 
            message.nonce, 
            message.ciphertext, 
            message.auth_tag, 
            message.aad.encode() if message.aad else None
        )
        return plaintext.decode()
    except Exception:
        return "[Error: Decryption Failed - Tamper Detected]"
