"""
Database Manager for QuantumNet

This module provides database management functionality including
user management, message storage, and security event logging.
"""

import os
import sqlite3
import hashlib
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import json


class DatabaseManager:
    """
    DatabaseManager class for handling all database operations.
    
    This class provides functionality for user management, message storage,
    and security event logging using SQLite.
    """
    
    def __init__(self, db_path: str = "data/quantumnet.db"):
        """
        Initialize the database manager.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize database
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create users table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        is_active BOOLEAN DEFAULT 1
                    )
                ''')
                
                # Create messages table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        content TEXT NOT NULL,
                        encrypted_content TEXT,
                        encryption_used BOOLEAN DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')
                
                # Create security_events table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS security_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        event_type TEXT NOT NULL,
                        description TEXT,
                        threat_level TEXT DEFAULT 'LOW',
                        ml_prediction TEXT,
                        confidence REAL,
                        metadata TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')
                
                # Create sessions table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        session_id TEXT UNIQUE NOT NULL,
                        key_id TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP,
                        is_active BOOLEAN DEFAULT 1,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')
                
                conn.commit()
                print("Database initialized successfully")
                
        except Exception as e:
            print(f"Database initialization failed: {e}")
    
    def create_user(self, username: str, email: str, password: str) -> Optional[int]:
        """
        Create a new user.
        
        Args:
            username: Username
            email: Email address
            password: Plain text password
            
        Returns:
            User ID if successful, None otherwise
        """
        try:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, email, password_hash)
                    VALUES (?, ?, ?)
                ''', (username, email, password_hash))
                
                user_id = cursor.lastrowid
                conn.commit()
                
                return user_id
                
        except sqlite3.IntegrityError:
            return None
        except Exception as e:
            print(f"Error creating user: {e}")
            return None
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """
        Authenticate a user.
        
        Args:
            username: Username
            password: Plain text password
            
        Returns:
            User dictionary if successful, None otherwise
        """
        try:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, username, email, created_at, last_login
                    FROM users
                    WHERE username = ? AND password_hash = ? AND is_active = 1
                ''', (username, password_hash))
                
                user = cursor.fetchone()
                
                if user:
                    # Update last login
                    cursor.execute('''
                        UPDATE users SET last_login = CURRENT_TIMESTAMP
                        WHERE id = ?
                    ''', (user[0],))
                    conn.commit()
                    
                    return {
                        'id': user[0],
                        'username': user[1],
                        'email': user[2],
                        'created_at': user[3],
                        'last_login': user[4]
                    }
                
                return None
                
        except Exception as e:
            print(f"Error authenticating user: {e}")
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """
        Get user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            User dictionary if found, None otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, username, email, created_at, last_login
                    FROM users
                    WHERE id = ? AND is_active = 1
                ''', (user_id,))
                
                user = cursor.fetchone()
                
                if user:
                    return {
                        'id': user[0],
                        'username': user[1],
                        'email': user[2],
                        'created_at': user[3],
                        'last_login': user[4]
                    }
                
                return None
                
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """
        Get user by username.
        
        Args:
            username: Username
            
        Returns:
            User dictionary if found, None otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, username, email, created_at, last_login
                    FROM users
                    WHERE username = ? AND is_active = 1
                ''', (username,))
                
                user = cursor.fetchone()
                
                if user:
                    return {
                        'id': user[0],
                        'username': user[1],
                        'email': user[2],
                        'created_at': user[3],
                        'last_login': user[4]
                    }
                
                return None
                
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    
    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """
        Get user by email.
        
        Args:
            email: Email address
            
        Returns:
            User dictionary if found, None otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, username, email, created_at, last_login
                    FROM users
                    WHERE email = ? AND is_active = 1
                ''', (email,))
                
                user = cursor.fetchone()
                
                if user:
                    return {
                        'id': user[0],
                        'username': user[1],
                        'email': user[2],
                        'created_at': user[3],
                        'last_login': user[4]
                    }
                
                return None
                
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    
    def create_message(self, user_id: int, content: str, 
                      encrypted_content: Optional[str] = None,
                      encryption_used: bool = False) -> Optional[int]:
        """
        Create a new message.
        
        Args:
            user_id: User ID
            content: Message content
            encrypted_content: Encrypted content (optional)
            encryption_used: Whether encryption was used
            
        Returns:
            Message ID if successful, None otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO messages (user_id, content, encrypted_content, encryption_used)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, content, encrypted_content, encryption_used))
                
                message_id = cursor.lastrowid
                conn.commit()
                
                return message_id
                
        except Exception as e:
            print(f"Error creating message: {e}")
            return None
    
    def get_recent_messages(self, limit: int = 50) -> List[Dict]:
        """
        Get recent messages.
        
        Args:
            limit: Maximum number of messages to return
            
        Returns:
            List of message dictionaries
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT m.id, m.user_id, u.username, m.content, m.encryption_used, m.created_at
                    FROM messages m
                    JOIN users u ON m.user_id = u.id
                    ORDER BY m.created_at DESC
                    LIMIT ?
                ''', (limit,))
                
                messages = []
                for row in cursor.fetchall():
                    messages.append({
                        'id': row[0],
                        'user_id': row[1],
                        'username': row[2],
                        'content': row[3],
                        'encryption_used': bool(row[4]),
                        'created_at': row[5]
                    })
                
                return messages
                
        except Exception as e:
            print(f"Error getting messages: {e}")
            return []
    
    def get_user_message_count(self, user_id: int) -> int:
        """
        Get message count for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Message count
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(*) FROM messages WHERE user_id = ?
                ''', (user_id,))
                
                count = cursor.fetchone()[0]
                return count
                
        except Exception as e:
            print(f"Error getting message count: {e}")
            return 0
    
    def create_security_event(self, user_id: int, event_type: str, 
                            description: str, threat_level: str = 'LOW',
                            metadata: Optional[Dict] = None) -> Optional[int]:
        """
        Create a security event.
        
        Args:
            user_id: User ID
            event_type: Type of security event
            description: Event description
            threat_level: Threat level (LOW, MEDIUM, HIGH, CRITICAL)
            metadata: Additional metadata (optional)
            
        Returns:
            Event ID if successful, None otherwise
        """
        try:
            metadata_json = json.dumps(metadata) if metadata else None
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO security_events (user_id, event_type, description, threat_level, metadata)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, event_type, description, threat_level, metadata_json))
                
                event_id = cursor.lastrowid
                conn.commit()
                
                return event_id
                
        except Exception as e:
            print(f"Error creating security event: {e}")
            return None
    
    def get_user_security_events(self, user_id: int, limit: int = 50) -> List[Dict]:
        """
        Get security events for a user.
        
        Args:
            user_id: User ID
            limit: Maximum number of events to return
            
        Returns:
            List of security event dictionaries
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, event_type, description, threat_level, ml_prediction, confidence, metadata, created_at
                    FROM security_events
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                ''', (user_id, limit))
                
                events = []
                for row in cursor.fetchall():
                    metadata = json.loads(row[6]) if row[6] else {}
                    events.append({
                        'id': row[0],
                        'event_type': row[1],
                        'description': row[2],
                        'threat_level': row[3],
                        'ml_prediction': row[4],
                        'confidence': row[5],
                        'metadata': metadata,
                        'created_at': row[7]
                    })
                
                return events
                
        except Exception as e:
            print(f"Error getting security events: {e}")
            return []
    
    def get_user_security_events_count(self, user_id: int) -> int:
        """
        Get security event count for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Event count
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(*) FROM security_events WHERE user_id = ?
                ''', (user_id,))
                
                count = cursor.fetchone()[0]
                return count
                
        except Exception as e:
            print(f"Error getting security event count: {e}")
            return 0
    
    def update_security_event(self, event_id: int, ml_prediction: Optional[str] = None,
                             threat_level: Optional[str] = None, confidence: Optional[float] = None) -> bool:
        """
        Update a security event.
        
        Args:
            event_id: Event ID
            ml_prediction: ML prediction (optional)
            threat_level: Threat level (optional)
            confidence: Confidence score (optional)
            
        Returns:
            True if successful
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Build update query dynamically
                updates = []
                params = []
                
                if ml_prediction is not None:
                    updates.append("ml_prediction = ?")
                    params.append(ml_prediction)
                
                if threat_level is not None:
                    updates.append("threat_level = ?")
                    params.append(threat_level)
                
                if confidence is not None:
                    updates.append("confidence = ?")
                    params.append(confidence)
                
                if updates:
                    params.append(event_id)
                    query = f"UPDATE security_events SET {', '.join(updates)} WHERE id = ?"
                    cursor.execute(query, params)
                    conn.commit()
                
                return True
                
        except Exception as e:
            print(f"Error updating security event: {e}")
            return False
    
    def create_session(self, user_id: int, session_id: str, key_id: Optional[str] = None,
                      expires_at: Optional[str] = None) -> Optional[int]:
        """
        Create a new session.
        
        Args:
            user_id: User ID
            session_id: Session identifier
            key_id: Quantum key ID (optional)
            expires_at: Expiration timestamp (optional)
            
        Returns:
            Session ID if successful, None otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO sessions (user_id, session_id, key_id, expires_at)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, session_id, key_id, expires_at))
                
                session_id = cursor.lastrowid
                conn.commit()
                
                return session_id
                
        except Exception as e:
            print(f"Error creating session: {e}")
            return None
    
    def get_active_sessions(self, user_id: int) -> List[Dict]:
        """
        Get active sessions for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of session dictionaries
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, session_id, key_id, created_at, expires_at
                    FROM sessions
                    WHERE user_id = ? AND is_active = 1
                    ORDER BY created_at DESC
                ''', (user_id,))
                
                sessions = []
                for row in cursor.fetchall():
                    sessions.append({
                        'id': row[0],
                        'session_id': row[1],
                        'key_id': row[2],
                        'created_at': row[3],
                        'expires_at': row[4]
                    })
                
                return sessions
                
        except Exception as e:
            print(f"Error getting sessions: {e}")
            return []
    
    def deactivate_session(self, session_id: str) -> bool:
        """
        Deactivate a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if successful
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE sessions SET is_active = 0 WHERE session_id = ?
                ''', (session_id,))
                
                conn.commit()
                return True
                
        except Exception as e:
            print(f"Error deactivating session: {e}")
            return False
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions.
        
        Returns:
            Number of sessions cleaned up
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE sessions 
                    SET is_active = 0 
                    WHERE expires_at < CURRENT_TIMESTAMP AND is_active = 1
                ''')
                
                cleaned_count = cursor.rowcount
                conn.commit()
                
                return cleaned_count
                
        except Exception as e:
            print(f"Error cleaning up sessions: {e}")
            return 0
    
    def get_database_stats(self) -> Dict:
        """
        Get database statistics.
        
        Returns:
            Dictionary containing database statistics
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # User count
                cursor.execute('SELECT COUNT(*) FROM users WHERE is_active = 1')
                stats['active_users'] = cursor.fetchone()[0]
                
                # Message count
                cursor.execute('SELECT COUNT(*) FROM messages')
                stats['total_messages'] = cursor.fetchone()[0]
                
                # Security events count
                cursor.execute('SELECT COUNT(*) FROM security_events')
                stats['total_security_events'] = cursor.fetchone()[0]
                
                # Active sessions count
                cursor.execute('SELECT COUNT(*) FROM sessions WHERE is_active = 1')
                stats['active_sessions'] = cursor.fetchone()[0]
                
                return stats
                
        except Exception as e:
            print(f"Error getting database stats: {e}")
            return {}
