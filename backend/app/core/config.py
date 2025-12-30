import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    PROJECT_NAME: str = "QuantumNet"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "supersecretkey_change_me_in_production_to_something_secure")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Database
    # Using SQLite for local demo reliability
    # Use absolute path to ensure DB is found regardless of CWD
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite+aiosqlite:///{os.path.join(BASE_DIR, 'quantumnet.db')}")
    
    # Master Key for encrypting keys at rest (32 bytes hex)
    MASTER_KEY_HEX: str = os.getenv("MASTER_KEY_HEX", "0000000000000000000000000000000000000000000000000000000000000000")

settings = Settings()
