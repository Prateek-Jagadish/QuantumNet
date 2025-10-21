"""
Database Models for QuantumNet

This module defines database models and ORM functionality
for the QuantumNet application.
"""

from datetime import datetime
from typing import Optional, Dict, Any
import json


class User:
    """User model for database operations."""
    
    def __init__(self, id: Optional[int] = None, username: str = "", 
                 email: str = "", password_hash: str = "", 
                 created_at: Optional[datetime] = None,
                 last_login: Optional[datetime] = None,
                 is_active: bool = True):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.created_at = created_at or datetime.now()
        self.last_login = last_login
        self.is_active = is_active
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """Create user from dictionary."""
        return cls(
            id=data.get('id'),
            username=data.get('username', ''),
            email=data.get('email', ''),
            password_hash=data.get('password_hash', ''),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None,
            last_login=datetime.fromisoformat(data['last_login']) if data.get('last_login') else None,
            is_active=data.get('is_active', True)
        )


class Message:
    """Message model for database operations."""
    
    def __init__(self, id: Optional[int] = None, user_id: int = 0,
                 content: str = "", encrypted_content: Optional[str] = None,
                 encryption_used: bool = False,
                 created_at: Optional[datetime] = None):
        self.id = id
        self.user_id = user_id
        self.content = content
        self.encrypted_content = encrypted_content
        self.encryption_used = encryption_used
        self.created_at = created_at or datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'content': self.content,
            'encrypted_content': self.encrypted_content,
            'encryption_used': self.encryption_used,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Message':
        """Create message from dictionary."""
        return cls(
            id=data.get('id'),
            user_id=data.get('user_id', 0),
            content=data.get('content', ''),
            encrypted_content=data.get('encrypted_content'),
            encryption_used=data.get('encryption_used', False),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None
        )


class SecurityEvent:
    """Security event model for database operations."""
    
    def __init__(self, id: Optional[int] = None, user_id: int = 0,
                 event_type: str = "", description: str = "",
                 threat_level: str = "LOW", ml_prediction: Optional[str] = None,
                 confidence: Optional[float] = None,
                 metadata: Optional[Dict] = None,
                 created_at: Optional[datetime] = None):
        self.id = id
        self.user_id = user_id
        self.event_type = event_type
        self.description = description
        self.threat_level = threat_level
        self.ml_prediction = ml_prediction
        self.confidence = confidence
        self.metadata = metadata or {}
        self.created_at = created_at or datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert security event to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'event_type': self.event_type,
            'description': self.description,
            'threat_level': self.threat_level,
            'ml_prediction': self.ml_prediction,
            'confidence': self.confidence,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityEvent':
        """Create security event from dictionary."""
        return cls(
            id=data.get('id'),
            user_id=data.get('user_id', 0),
            event_type=data.get('event_type', ''),
            description=data.get('description', ''),
            threat_level=data.get('threat_level', 'LOW'),
            ml_prediction=data.get('ml_prediction'),
            confidence=data.get('confidence'),
            metadata=data.get('metadata', {}),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None
        )


class Session:
    """Session model for database operations."""
    
    def __init__(self, id: Optional[int] = None, user_id: int = 0,
                 session_id: str = "", key_id: Optional[str] = None,
                 created_at: Optional[datetime] = None,
                 expires_at: Optional[datetime] = None,
                 is_active: bool = True):
        self.id = id
        self.user_id = user_id
        self.session_id = session_id
        self.key_id = key_id
        self.created_at = created_at or datetime.now()
        self.expires_at = expires_at
        self.is_active = is_active
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'key_id': self.key_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_active': self.is_active
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Session':
        """Create session from dictionary."""
        return cls(
            id=data.get('id'),
            user_id=data.get('user_id', 0),
            session_id=data.get('session_id', ''),
            key_id=data.get('key_id'),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None,
            expires_at=datetime.fromisoformat(data['expires_at']) if data.get('expires_at') else None,
            is_active=data.get('is_active', True)
        )
    
    def is_expired(self) -> bool:
        """Check if session is expired."""
        if not self.expires_at:
            return False
        return datetime.now() > self.expires_at
