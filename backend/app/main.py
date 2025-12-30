from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api import auth, chat, dashboard, contacts
from app.database import engine, Base
import socketio

print("DEBUG: Loading main.py from disk...")

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Socket.IO
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')

# Mount Socket.IO on the FastAPI app
sio_asgi_app = socketio.ASGIApp(sio, other_asgi_app=app)

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
from app.api import dashboard
app.include_router(dashboard.router, prefix="/api/v1/security", tags=["security"])
from app.api import chat
app.include_router(chat.router, prefix="/api/v1/chat", tags=["chat"])
from app.api import contacts
app.include_router(contacts.router, prefix="/api/v1/contacts", tags=["contacts"])

# Import Websocket Events
from app.websocket import server

@app.get("/")
async def root():
    return {"message": "QuantumNet Secure Gateway Active"}

# Export the combined app (FastAPI + Socket.IO)
app = sio_asgi_app
