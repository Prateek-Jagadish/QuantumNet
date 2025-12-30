import socketio
from app.main import sio
from app.database import AsyncSessionLocal
from app.services import chat_service
from app.core.security import jwt, settings
from app.models.user import User
from sqlalchemy.future import select
import binascii
import uuid

# Map socket_id to user_id
connected_users = {}

@sio.event
async def connect(sid, environ):
    print(f"Client connected: {sid}")
    # Auth check usually happens here or in a handshake
    # We expect token in query params or headers
    # For simplicity, we'll wait for 'authenticate' event or check headers if possible
    pass

@sio.event
async def authenticate(sid, data):
    token = data.get("token")
    if not token:
        return False
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username = payload.get("sub")
        
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(User).where(User.username == username))
            user = result.scalars().first()
            if user:
                connected_users[sid] = str(user.id)
                # Join a room with their user_id so we can message them easily
                await sio.enter_room(sid, str(user.id))
                await sio.emit("auth_success", {"user_id": str(user.id)}, room=sid)
                print(f"User {username} authenticated on {sid}")
                
                # Send any offline messages (messages sent while user was offline)
                from app.models.message import Message
                offline_result = await db.execute(
                    select(Message).where(
                        (Message.recipient_id == user.id) & (Message.status != "read")
                    ).order_by(Message.sent_at)
                )
                offline_messages = offline_result.scalars().all()
                print(f"Found {len(offline_messages)} offline messages for user {user.id}")
                
                for msg in offline_messages:
                    try:
                        decrypted_content = await chat_service.decrypt_message_content(db, msg)
                        payload = {
                            "id": str(msg.id),
                            "sender_id": str(msg.sender_id),
                            "content": decrypted_content,
                            "ciphertext": binascii.hexlify(msg.ciphertext).decode(),
                            "nonce": binascii.hexlify(msg.nonce).decode(),
                            "timestamp": msg.sent_at.isoformat(),
                            "type": msg.message_type
                        }
                        await sio.emit("receive_message", payload, room=sid)
                        print(f"Sent offline message {msg.id} to user {user.id}")
                    except Exception as msg_err:
                        print(f"Error sending offline message {msg.id}: {msg_err}")
            else:
                await sio.disconnect(sid)
    except Exception as e:
        print(f"Auth failed: {e}")
        import traceback
        traceback.print_exc()
        await sio.disconnect(sid)

@sio.event
async def send_message(sid, data):
    # data: {recipient_id: str, content: str, type: str}
    sender_id = connected_users.get(sid)
    if not sender_id:
        return
        
    recipient_id = data.get("recipient_id")
    content = data.get("content")
    msg_type = data.get("type", "text")
    
    print(f"DEBUG: send_message called with data: {data}")
    try:
        async with AsyncSessionLocal() as db:
            # Convert to UUID
            print(f"DEBUG: Converting IDs to UUIDs. Sender: {sender_id}, Recipient: {recipient_id}")
            sender_uuid = uuid.UUID(sender_id)
            recipient_uuid = uuid.UUID(recipient_id)

            # Encrypt and Store
            print("DEBUG: Calling chat_service.send_encrypted_message...")
            msg = await chat_service.send_encrypted_message(db, sender_uuid, recipient_uuid, content, msg_type)
            print(f"DEBUG: Message stored with ID: {msg.id}")
            
            # Decrypt for sending to recipient (Simulating the client receiving it and decrypting)
            # In a real E2EE app, we'd send the ciphertext.
            # But here, the frontend expects to show the message.
            # If we send ciphertext, the frontend needs the key.
            # To keep the frontend simple (as requested "React 18... Socket.IO"), 
            # we can send the ciphertext AND the decrypted content (for display) 
            # OR we send ciphertext and the frontend requests the key?
            # Let's send the decrypted content for the "Chat View" and the ciphertext for the "Inspector View".
            
            decrypted_content = await chat_service.decrypt_message_content(db, msg)
            print(f"DEBUG: Decrypted content: {decrypted_content}")
            
            payload = {
                "id": str(msg.id),
                "sender_id": sender_id,
                "content": decrypted_content, # For UI
                "ciphertext": binascii.hexlify(msg.ciphertext).decode(), # For Demo/Inspector
                "nonce": binascii.hexlify(msg.nonce).decode(),
                "timestamp": msg.sent_at.isoformat(),
                "type": msg_type
            }
            
            # Send to Recipient
            print(f"DEBUG: Emitting to recipient room: {recipient_id}")
            await sio.emit("receive_message", payload, room=recipient_id)
            
            # Send back to Sender (for their UI)
            print(f"DEBUG: Emitting to sender room: {sid}")
            await sio.emit("message_sent", payload, room=sid)
    except Exception as e:
        print(f"CRITICAL ERROR in send_message: {e}")
        import traceback
        traceback.print_exc()

@sio.event
async def mark_read(sid, data):
    # data: {message_id: str, sender_id: str}
    message_id = data.get("message_id")
    sender_id = data.get("sender_id")
    
    if not message_id or not sender_id:
        return
        
    async with AsyncSessionLocal() as db:
        from app.models.message import Message
        from datetime import datetime
        
        # Update Message
        result = await db.execute(select(Message).where(Message.id == uuid.UUID(message_id)))
        msg = result.scalars().first()
        
        if msg and not msg.read_at:
            msg.read_at = datetime.utcnow()
            msg.status = "read"
            await db.commit()
            
            # Notify Sender
            # We need to find sender's socket
            # connected_users maps sid -> user_id. We need user_id -> sid?
            # We joined rooms with user_id, so we can emit to room(sender_id)
            
            await sio.emit("message_read", {"message_id": message_id, "read_at": msg.read_at.isoformat()}, room=sender_id)

@sio.event
async def disconnect(sid):
    if sid in connected_users:
        del connected_users[sid]
    print(f"Client disconnected: {sid}")
