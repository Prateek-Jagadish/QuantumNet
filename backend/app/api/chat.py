from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.services import chat_service
from app.models.user import User
from app.core.security import oauth2_scheme, jwt, settings
import shutil
import os
import uuid

router = APIRouter()

UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
    from sqlalchemy.future import select
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalars().first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

@router.post("/upload")
async def upload_file(
    recipient_id: str,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # 1. Save File Temporarily
    file_ext = file.filename.split(".")[-1]
    file_id = str(uuid.uuid4())
    filename = f"{file_id}.{file_ext}"
    file_path = os.path.join(UPLOAD_DIR, filename)
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    # 2. Encrypt File
    with open(file_path, "rb") as f:
        data = f.read()
        
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    file_key = os.urandom(32)
    aesgcm = AESGCM(file_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    
    # Write encrypted file
    encrypted_path = file_path + ".enc"
    with open(encrypted_path, "wb") as f:
        f.write(nonce + ciphertext)
        
    # Remove original plaintext file
    os.remove(file_path)
    
    # 3. Send Message with File Key (Encrypted)
    import json
    import binascii
    
    file_key_hex = binascii.hexlify(file_key).decode()
    
    content_payload = json.dumps({
        "text": f"Sent a file: {file.filename}",
        "file_key_hex": file_key_hex,
        # Append key to URL so the browser can just "click to download" (decrypted on server)
        "download_url": f"/api/v1/chat/download/{filename}.enc?key={file_key_hex}"
    })
    
    msg_type = "photo" if file.content_type.startswith("image/") else "file"
    
    msg = await chat_service.send_encrypted_message(
        db, 
        current_user.id, 
        uuid.UUID(recipient_id), 
        content_payload, 
        msg_type,
        file_meta={"url": filename + ".enc", "name": file.filename, "size": len(data)}
    )
    
    return {"message": "File uploaded and sent", "message_id": str(msg.id)}

@router.get("/download/{filename}")
async def download_file(filename: str, key: str = None):
    path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File not found")
        
    if not key:
        # If no key provided, serve encrypted file (default behavior)
        from fastapi.responses import FileResponse
        return FileResponse(path)
        
    # If key is provided, decrypt on the fly
    try:
        import binascii
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from fastapi.responses import StreamingResponse
        import io
        
        file_key = binascii.unhexlify(key)
        aesgcm = AESGCM(file_key)
        
        with open(path, "rb") as f:
            encrypted_data = f.read()
            
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Determine original filename (remove .enc and uuid if possible, but here we just remove .enc)
        original_filename = filename.replace(".enc", "")
        # Ideally we stored the original name in DB, but for this endpoint we just serve content.
        # The browser will save as the last part of URL usually, or Content-Disposition.
        
        return StreamingResponse(
            io.BytesIO(plaintext),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{original_filename}"'}
        )
        
    except Exception as e:
        print(f"Decryption failed during download: {e}")
        raise HTTPException(status_code=400, detail="Decryption failed")

@router.get("/history/{recipient_id}")
async def get_history(
    recipient_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    from sqlalchemy import or_, and_
    from app.models.message import Message
    
    # Fetch messages where (sender=me AND recipient=them) OR (sender=them AND recipient=me)
    from sqlalchemy.future import select
    stmt = select(Message).where(
        or_(
            and_(Message.sender_id == current_user.id, Message.recipient_id == uuid.UUID(recipient_id)),
            and_(Message.sender_id == uuid.UUID(recipient_id), Message.recipient_id == current_user.id)
        )
    ).order_by(Message.sent_at)
    
    result = await db.execute(stmt)
    messages = result.scalars().all()
    
    # We need to decrypt these messages before sending them to the frontend
    # In a real E2EE app, the frontend would fetch encrypted blobs and decrypt them.
    # For this demo, since our "E2EE" is simulated on the backend (the backend acts as the secure enclave),
    # we will decrypt them here using the session key we have stored.
    
    decrypted_messages = []
    for msg in messages:
        # Decrypt content
        content = await chat_service.decrypt_message_content(db, msg)
            
        decrypted_messages.append({
            "id": str(msg.id),
            "sender_id": str(msg.sender_id),
            "recipient_id": str(msg.recipient_id),
            "content": content,
            "timestamp": msg.sent_at.isoformat(),
            "type": msg.message_type
        })
        
    return decrypted_messages
