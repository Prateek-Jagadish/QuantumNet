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
                        bio TEXT,
                        phone TEXT,
                        profile_photo_path TEXT,
                        failed_attempts INTEGER DEFAULT 0,
                        lockout_until TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_online BOOLEAN DEFAULT 0,
                        is_active BOOLEAN DEFAULT 1
                    )
                ''')
                
                # Create messages table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender_id INTEGER NOT NULL,
                        recipient_id INTEGER NOT NULL,
                        content TEXT NOT NULL,
                        encrypted_content TEXT,
                        encryption_used BOOLEAN DEFAULT 0,
                        status TEXT DEFAULT 'pending',
                        delivered_at TIMESTAMP,
                        read_at TIMESTAMP,
                        reply_to INTEGER,
                        is_deleted_sender BOOLEAN DEFAULT 0,
                        is_deleted_recipient BOOLEAN DEFAULT 0,
                        reactions TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (sender_id) REFERENCES users (id),
                        FOREIGN KEY (recipient_id) REFERENCES users (id)
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
                
                # Create devices table for multi-device support
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS devices (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        device_id TEXT NOT NULL,
                        device_name TEXT,
                        browser TEXT,
                        os TEXT,
                        ip_address TEXT,
                        last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_active BOOLEAN DEFAULT 1,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')
                
                # Create file_shares table for file sharing
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS file_shares (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender_id INTEGER NOT NULL,
                        recipient_id INTEGER NOT NULL,
                        file_name TEXT NOT NULL,
                        file_type TEXT NOT NULL,
                        file_size INTEGER NOT NULL,
                        encrypted_content BLOB NOT NULL,
                        encryption_used BOOLEAN DEFAULT 0,
                        thumbnail_path TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (sender_id) REFERENCES users (id),
                        FOREIGN KEY (recipient_id) REFERENCES users (id)
                    )
                ''')

                # Contacts table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS contacts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        contact_id INTEGER NOT NULL,
                        status TEXT NOT NULL DEFAULT 'normal',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(user_id, contact_id),
                        FOREIGN KEY (user_id) REFERENCES users (id),
                        FOREIGN KEY (contact_id) REFERENCES users (id)
                    )
                ''')
                
                conn.commit()
                print("Database initialized successfully")
                # Apply lightweight migrations to add missing columns in existing DBs
                self._apply_sqlite_migrations(conn)
                
        except Exception as e:
            print(f"Database initialization failed: {e}")

    def _apply_sqlite_migrations(self, conn: sqlite3.Connection):
        """Ensure required columns exist on legacy installations."""
        try:
            cursor = conn.cursor()
            # Users table: ensure last_seen, is_online columns
            cursor.execute("PRAGMA table_info(users)")
            user_cols = {row[1] for row in cursor.fetchall()}
            if 'failed_attempts' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")
            if 'lockout_until' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN lockout_until TIMESTAMP")
            if 'photo_hash' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN photo_hash TEXT")
            if 'totp_secret' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
            if 'email_verified' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT 0")
            if 'email_verification_token' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN email_verification_token TEXT")
            if 'reset_token' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN reset_token TEXT")
            if 'reset_expires' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN reset_expires TIMESTAMP")
            if 'bio' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN bio TEXT")
            if 'phone' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN phone TEXT")
            if 'profile_photo_path' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN profile_photo_path TEXT")
            if 'last_seen' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN last_seen TIMESTAMP")
                cursor.execute("UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE last_seen IS NULL")
            if 'is_online' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN is_online BOOLEAN")
                cursor.execute("UPDATE users SET is_online = 0 WHERE is_online IS NULL")
            if 'bio' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN bio TEXT")
            if 'phone' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN phone TEXT")
            if 'profile_photo_path' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN profile_photo_path TEXT")

            # Messages table: ensure modern columns
            cursor.execute("PRAGMA table_info(messages)")
            msg_cols = {row[1] for row in cursor.fetchall()}
            def add_col(name, ddl):
                if name not in msg_cols:
                    cursor.execute(f"ALTER TABLE messages ADD COLUMN {ddl}")
            add_col('sender_id', 'sender_id INTEGER NOT NULL DEFAULT 0')
            add_col('recipient_id', 'recipient_id INTEGER NOT NULL DEFAULT 0')
            add_col('encrypted_content', 'encrypted_content TEXT')
            add_col('iv', 'iv TEXT')
            add_col('encryption_used', "encryption_used BOOLEAN DEFAULT 0")
            add_col('status', "status TEXT")
            add_col('delivered_at', 'delivered_at TIMESTAMP')
            add_col('read_at', 'read_at TIMESTAMP')
            add_col('reply_to', 'reply_to INTEGER')
            add_col('is_deleted_sender', 'is_deleted_sender BOOLEAN DEFAULT 0')
            add_col('is_deleted_recipient', 'is_deleted_recipient BOOLEAN DEFAULT 0')
            add_col('reactions', 'reactions TEXT')
            add_col('created_at', 'created_at TIMESTAMP')

            # Backfill reasonable defaults where NULL
            cursor.execute("UPDATE messages SET status = 'pending' WHERE status IS NULL")
            cursor.execute("UPDATE messages SET is_deleted_sender = 0 WHERE is_deleted_sender IS NULL")
            cursor.execute("UPDATE messages SET is_deleted_recipient = 0 WHERE is_deleted_recipient IS NULL")
            cursor.execute("UPDATE messages SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP)")

            # Contacts table: ensure exists
            cursor.execute("PRAGMA table_info(contacts)")
            # If table_info returns empty and table doesn't exist, create (safety)
            if cursor.fetchall() == []:
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS contacts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        contact_id INTEGER NOT NULL,
                        status TEXT NOT NULL DEFAULT 'normal',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(user_id, contact_id)
                    )
                ''')

            conn.commit()
        except Exception as e:
            print(f"SQLite migration check failed: {e}")

    def get_user_auth_record(self, username: str) -> Optional[Dict]:
        """Fetch user auth record including password hash and lockout fields."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, username, email, password_hash, failed_attempts, lockout_until, is_active
                    FROM users WHERE username = ?
                ''', (username,))
                row = cursor.fetchone()
                if not row:
                    return None
                return {
                    'id': row[0],
                    'username': row[1],
                    'email': row[2],
                    'password_hash': row[3],
                    'failed_attempts': row[4] or 0,
                    'lockout_until': row[5],
                    'is_active': bool(row[6])
                }
        except Exception as e:
            print(f"Error fetching auth record: {e}")
            return None

    def record_failed_login(self, user_id: int, max_attempts: int, lockout_minutes: int) -> None:
        """Increment failed attempts and set lockout when threshold exceeded."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT failed_attempts FROM users WHERE id = ?', (user_id,))
                row = cursor.fetchone()
                attempts = (row[0] or 0) + 1 if row else 1
                lockout_until = None
                if attempts >= max_attempts:
                    cursor.execute('UPDATE users SET failed_attempts = ?, lockout_until = datetime(\'now\', ?)', (attempts, f'+{lockout_minutes} minutes'))
                else:
                    cursor.execute('UPDATE users SET failed_attempts = ? WHERE id = ?', (attempts, user_id))
                conn.commit()
        except Exception as e:
            print(f"Error recording failed login: {e}")

    def reset_failed_login(self, user_id: int) -> None:
        """Reset failed attempts and clear lockout."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE id = ?', (user_id,))
                conn.commit()
        except Exception as e:
            print(f"Error resetting failed login: {e}")
    
    def create_user(self, username: str, email: str, password_hash: str) -> Optional[int]:
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

    def search_users(self, query: str, limit: int = 10) -> List[Dict]:
        """
        Search users by username or email (case-insensitive).
        """
        try:
            like = f"%{query.lower()}%"
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, username, email, last_seen, is_online
                    FROM users
                    WHERE is_active = 1 AND (lower(username) LIKE ? OR lower(email) LIKE ?)
                    ORDER BY username ASC
                    LIMIT ?
                ''', (like, like, limit))
                results = []
                for row in cursor.fetchall():
                    results.append({
                        'id': row[0],
                        'username': row[1],
                        'email': row[2],
                        'last_seen': row[3],
                        'is_online': bool(row[4])
                    })
                return results
        except Exception as e:
            print(f"Error searching users: {e}")
            return []
    
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
                    SELECT id, username, email, created_at, last_login, last_seen, is_online, bio, phone, profile_photo_path
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
                        'last_login': user[4],
                        'last_seen': user[5],
                        'is_online': bool(user[6]) if user[6] is not None else False,
                        'bio': user[7],
                        'phone': user[8],
                        'profile_photo_path': user[9]
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
    
    def create_message(self, sender_id: int, recipient_id: int, content: str, 
                     encrypted_content: Optional[str] = None,
                     encryption_used: bool = False,
                     reply_to: Optional[int] = None,
                     iv: Optional[str] = None) -> Optional[int]:
        """
        Create a new message.
        
        Args:
            sender_id: Sender user ID
            recipient_id: Recipient user ID
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
                    INSERT INTO messages (sender_id, recipient_id, content, encrypted_content, iv, encryption_used, reply_to)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (sender_id, recipient_id, content, encrypted_content, iv, encryption_used, reply_to))
                
                message_id = cursor.lastrowid
                conn.commit()
                
                return message_id
                
        except Exception as e:
            print(f"Error creating message: {e}")
            return None
    
    def get_recent_messages(self, limit: int = 50, offset: int = 0) -> List[Dict]:
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
                    SELECT m.id, m.sender_id, u.username, m.content, m.encryption_used, m.created_at, m.iv, m.encrypted_content
                    FROM messages m
                    JOIN users u ON m.sender_id = u.id
                    ORDER BY m.created_at DESC
                    LIMIT ? OFFSET ?
                ''', (limit, offset))
                
                messages = []
                for row in cursor.fetchall():
                    messages.append({
                        'id': row[0],
                        'user_id': row[1],
                        'username': row[2],
                        'content': row[3],
                        'encryption_used': bool(row[4]),
                        'created_at': row[5],
                        'iv': row[6],
                        'encrypted_content': row[7]
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
                    SELECT COUNT(*) FROM messages WHERE sender_id = ? OR recipient_id = ?
                ''', (user_id, user_id))
                
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
    
    def update_user_presence(self, user_id: int, is_online: bool = True) -> bool:
        """
        Update user online/offline status.
        
        Args:
            user_id: User ID
            is_online: Online status
            
        Returns:
            True if successful
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE users 
                    SET is_online = ?, last_seen = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (is_online, user_id))
                
                conn.commit()
                return True
                
        except Exception as e:
            print(f"Error updating user presence: {e}")
            return False
    
    def get_online_users(self) -> List[Dict]:
        """
        Get list of online users.
        
        Returns:
            List of online user dictionaries
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, username, last_seen
                    FROM users
                    WHERE is_online = 1 AND is_active = 1
                    ORDER BY last_seen DESC
                ''')
                
                users = []
                for row in cursor.fetchall():
                    users.append({
                        'id': row[0],
                        'username': row[1],
                        'last_seen': row[2]
                    })
                
                return users
                
        except Exception as e:
            print(f"Error getting online users: {e}")
            return []
    
    def create_device(self, user_id: int, device_id: str, device_name: str = None,
                     browser: str = None, os: str = None, ip_address: str = None) -> Optional[int]:
        """
        Create or update device record.
        
        Args:
            user_id: User ID
            device_id: Device identifier
            device_name: Device name
            browser: Browser name
            os: Operating system
            ip_address: IP address
            
        Returns:
            Device ID if successful, None otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if device exists
                cursor.execute('''
                    SELECT id FROM devices 
                    WHERE user_id = ? AND device_id = ?
                ''', (user_id, device_id))
                
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing device
                    cursor.execute('''
                        UPDATE devices 
                        SET last_active = CURRENT_TIMESTAMP, is_active = 1
                        WHERE id = ?
                    ''', (existing[0],))
                    device_id = existing[0]
                else:
                    # Create new device
                    cursor.execute('''
                        INSERT INTO devices (user_id, device_id, device_name, browser, os, ip_address)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (user_id, device_id, device_name, browser, os, ip_address))
                    device_id = cursor.lastrowid
                
                conn.commit()
                return device_id
                
        except Exception as e:
            print(f"Error creating device: {e}")
            return None
    
    def deactivate_device(self, device_id: str) -> bool:
        """
        Deactivate a device.
        
        Args:
            device_id: Device identifier
            
        Returns:
            True if successful
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE devices SET is_active = 0 WHERE device_id = ?
                ''', (device_id,))
                
                conn.commit()
                return True
                
        except Exception as e:
            print(f"Error deactivating device: {e}")
            return False
    
    def update_message_status(self, message_id: int, status: str) -> bool:
        """
        Update message delivery/read status.
        
        Args:
            message_id: Message ID
            status: New status (delivered, read)
            
        Returns:
            True if successful
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if status == 'delivered':
                    cursor.execute('''
                        UPDATE messages 
                        SET status = 'delivered', delivered_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    ''', (message_id,))
                elif status == 'read':
                    cursor.execute('''
                        UPDATE messages 
                        SET status = 'read', read_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    ''', (message_id,))
                
                conn.commit()
                return True
                
        except Exception as e:
            print(f"Error updating message status: {e}")
            return False

    def get_message_sender(self, message_id: int) -> Optional[int]:
        """Return sender_id for a given message id."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT sender_id FROM messages WHERE id = ?', (message_id,))
                row = cursor.fetchone()
                return row[0] if row else None
        except Exception as e:
            print(f"Error fetching message sender: {e}")
            return None
    
    def get_messages_between_users(self, user1_id: int, user2_id: int, limit: int = 50, offset: int = 0) -> List[Dict]:
        """
        Get messages between two users.
        
        Args:
            user1_id: First user ID
            user2_id: Second user ID
            limit: Maximum number of messages
            
        Returns:
            List of message dictionaries
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT m.id, m.sender_id, m.recipient_id, u.username, m.content, 
                           m.encryption_used, m.status, m.delivered_at, m.read_at, m.created_at, m.iv, m.encrypted_content
                    FROM messages m
                    JOIN users u ON m.sender_id = u.id
                    WHERE (m.sender_id = ? AND m.recipient_id = ?) 
                       OR (m.sender_id = ? AND m.recipient_id = ?)
                    ORDER BY m.created_at DESC
                    LIMIT ? OFFSET ?
                ''', (user1_id, user2_id, user2_id, user1_id, limit, offset))
                
                messages = []
                for row in cursor.fetchall():
                    messages.append({
                        'id': row[0],
                        'sender_id': row[1],
                        'recipient_id': row[2],
                        'username': row[3],
                        'content': row[4],
                        'encryption_used': bool(row[5]),
                        'status': row[6],
                        'delivered_at': row[7],
                        'read_at': row[8],
                        'created_at': row[9],
                        'iv': row[10],
                        'encrypted_content': row[11]
                    })
                
                return messages
                
        except Exception as e:
            print(f"Error getting messages between users: {e}")
            return []

    def add_contact(self, user_id: int, contact_id: int, status: str = 'normal') -> bool:
        """Add or update a contact with status normal/favorite/blocked."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO contacts (user_id, contact_id, status)
                    VALUES (?, ?, ?)
                    ON CONFLICT(user_id, contact_id) DO UPDATE SET status=excluded.status
                ''', (user_id, contact_id, status))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error adding contact: {e}")
            return False

    def remove_contact(self, user_id: int, contact_id: int) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM contacts WHERE user_id = ? AND contact_id = ?', (user_id, contact_id))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error removing contact: {e}")
            return False

    def list_contacts(self, user_id: int) -> List[Dict]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT c.contact_id, u.username, u.email, c.status, u.is_online, u.last_seen,
                           COALESCE(uc.unread_count, 0) as unread_count
                    FROM contacts c
                    JOIN users u ON c.contact_id = u.id
                    LEFT JOIN (
                        SELECT sender_id, COUNT(*) as unread_count
                        FROM messages
                        WHERE recipient_id = ? AND (status IS NULL OR status <> 'read')
                        GROUP BY sender_id
                    ) uc ON uc.sender_id = c.contact_id
                    WHERE c.user_id = ?
                    ORDER BY (c.status = 'favorite') DESC, u.username ASC
                ''', (user_id, user_id))
                rows = cursor.fetchall()
                return [{
                    'id': r[0], 'username': r[1], 'email': r[2], 'status': r[3], 'is_online': bool(r[4]), 'last_seen': r[5], 'unread_count': r[6]
                } for r in rows]
        except Exception as e:
            print(f"Error listing contacts: {e}")
            return []

    def set_contact_status(self, user_id: int, contact_id: int, status: str) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE contacts SET status = ? WHERE user_id = ? AND contact_id = ?', (status, user_id, contact_id))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"Error setting contact status: {e}")
            return False

    def update_user_profile(self, user_id: int, bio: Optional[str], phone: Optional[str]) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET bio = ?, phone = ? WHERE id = ?', (bio, phone, user_id))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error updating profile: {e}")
            return False

    def update_profile_photo_path(self, user_id: int, path: str) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET profile_photo_path = ? WHERE id = ?', (path, user_id))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error updating profile photo: {e}")
            return False

    def update_profile_photo_hash(self, user_id: int, photo_hash: str) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET photo_hash = ? WHERE id = ?', (photo_hash, user_id))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error updating profile photo hash: {e}")
            return False

    def find_users_by_photo_hash(self, photo_hash: str, limit: int = 10) -> List[Dict]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id, username, email FROM users WHERE photo_hash = ? AND is_active = 1 LIMIT ?', (photo_hash, limit))
                return [{ 'id': r[0], 'username': r[1], 'email': r[2] } for r in cursor.fetchall()]
        except Exception as e:
            print(f"Error searching by photo hash: {e}")
            return []

    def set_user_totp_secret(self, user_id: int, secret: str) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET totp_secret = ? WHERE id = ?', (secret, user_id))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error setting TOTP secret: {e}")
            return False

    def get_user_totp_secret(self, user_id: int) -> Optional[str]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT totp_secret FROM users WHERE id = ?', (user_id,))
                row = cursor.fetchone()
                return row[0] if row and row[0] else None
        except Exception as e:
            print(f"Error getting TOTP secret: {e}")
            return None

    def set_email_verification_token(self, user_id: int, token: str) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET email_verification_token = ?, email_verified = 0 WHERE id = ?', (token, user_id))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error setting verification token: {e}")
            return False

    def verify_email_by_token(self, token: str) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET email_verified = 1, email_verification_token = NULL WHERE email_verification_token = ?', (token,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"Error verifying email: {e}")
            return False

    def set_password_reset(self, user_id: int, token: str, expires_at: str) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?', (token, expires_at, user_id))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error setting reset token: {e}")
            return False

    def get_user_by_reset_token(self, token: str) -> Optional[Dict]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id, reset_expires FROM users WHERE reset_token = ?', (token,))
                row = cursor.fetchone()
                if not row:
                    return None
                return { 'id': row[0], 'reset_expires': row[1] }
        except Exception as e:
            print(f"Error fetching reset token: {e}")
            return None

    def update_user_password_hash(self, user_id: int, password_hash: str) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET password_hash = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?', (password_hash, user_id))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error updating password: {e}")
            return False

    def search_messages(self, user_id: int, query: str, limit: int = 50, contact_id: Optional[int] = None, start: Optional[str] = None, end: Optional[str] = None) -> List[Dict]:
        try:
            like = f"%{query}%"
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                base = '''
                    SELECT m.id, m.sender_id, m.recipient_id, m.content, m.created_at
                    FROM messages m
                    WHERE (m.sender_id = ? OR m.recipient_id = ?) AND m.content LIKE ?
                '''
                params = [user_id, user_id, like]
                if contact_id and contact_id > 0:
                    base += ' AND (m.sender_id = ? OR m.recipient_id = ?)'
                    params.extend([contact_id, contact_id])
                if start:
                    base += ' AND m.created_at >= ?'
                    params.append(start)
                if end:
                    base += ' AND m.created_at <= ?'
                    params.append(end)
                base += ' ORDER BY m.created_at DESC LIMIT ?'
                params.append(limit)
                cursor.execute(base, tuple(params))
                rows = cursor.fetchall()
                return [{
                    'id': r[0], 'sender_id': r[1], 'recipient_id': r[2], 'content': r[3], 'created_at': r[4]
                } for r in rows]
        except Exception as e:
            print(f"Error searching messages: {e}")
            return []

    def react_to_message(self, message_id: int, emoji: str) -> bool:
        """Append a reaction emoji to message.reactions (JSON array in text)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT reactions FROM messages WHERE id = ?', (message_id,))
                row = cursor.fetchone()
                reactions = []
                if row and row[0]:
                    try:
                        reactions = json.loads(row[0])
                    except Exception:
                        reactions = []
                reactions.append(emoji)
                cursor.execute('UPDATE messages SET reactions = ? WHERE id = ?', (json.dumps(reactions), message_id))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error reacting to message: {e}")
            return False

    def mark_message_deleted(self, message_id: int, for_user_id: int) -> bool:
        """Delete for me: set flag based on whether user is sender or recipient."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT sender_id, recipient_id FROM messages WHERE id = ?', (message_id,))
                row = cursor.fetchone()
                if not row:
                    return False
                if row[0] == for_user_id:
                    cursor.execute('UPDATE messages SET is_deleted_sender = 1 WHERE id = ?', (message_id,))
                elif row[1] == for_user_id:
                    cursor.execute('UPDATE messages SET is_deleted_recipient = 1 WHERE id = ?', (message_id,))
                else:
                    return False
                conn.commit()
                return True
        except Exception as e:
            print(f"Error deleting message: {e}")
            return False

    def delete_message_for_everyone(self, message_id: int) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE messages SET content = "", encrypted_content = NULL, status = "deleted" WHERE id = ?', (message_id,))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error deleting message for everyone: {e}")
            return False
    
    def create_file_share(self, sender_id: int, recipient_id: int, file_name: str,
                         file_type: str, file_size: int, encrypted_content: bytes,
                         encryption_used: bool = False, thumbnail_path: Optional[str] = None) -> Optional[int]:
        """
        Create a file share record.
        
        Args:
            sender_id: Sender user ID
            recipient_id: Recipient user ID
            file_name: Name of the file
            file_type: MIME type of the file
            file_size: Size of the file in bytes
            encrypted_content: Encrypted file content
            encryption_used: Whether encryption was used
            
        Returns:
            File share ID if successful, None otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO file_shares (sender_id, recipient_id, file_name, file_type, 
                                           file_size, encrypted_content, encryption_used, thumbnail_path)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (sender_id, recipient_id, file_name, file_type, file_size, 
                      encrypted_content, encryption_used, thumbnail_path))
                
                file_share_id = cursor.lastrowid
                conn.commit()
                
                return file_share_id
                
        except Exception as e:
            print(f"Error creating file share: {e}")
            return None
    
    def get_file_share(self, file_id: int) -> Optional[Dict]:
        """
        Get a file share record.
        
        Args:
            file_id: File share ID
            
        Returns:
            File share dictionary if found, None otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, sender_id, recipient_id, file_name, file_type, 
                           file_size, encrypted_content, encryption_used, created_at
                    FROM file_shares
                    WHERE id = ?
                ''', (file_id,))
                
                file_share = cursor.fetchone()
                
                if file_share:
                    return {
                        'id': file_share[0],
                        'sender_id': file_share[1],
                        'recipient_id': file_share[2],
                        'file_name': file_share[3],
                        'file_type': file_share[4],
                        'file_size': file_share[5],
                        'encrypted_content': file_share[6],
                        'encryption_used': bool(file_share[7]),
                        'created_at': file_share[8]
                    }
                
                return None
                
        except Exception as e:
            print(f"Error getting file share: {e}")
            return None

    def list_media(self, user_id: int, contact_id: Optional[int], limit: int = 50, offset: int = 0) -> List[Dict]:
        """List file shares for a user optionally filtered by contact."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                base = '''
                    SELECT id, sender_id, recipient_id, file_name, file_type, file_size, encryption_used, thumbnail_path, created_at
                    FROM file_shares
                    WHERE (sender_id = ? OR recipient_id = ?)
                '''
                params = [user_id, user_id]
                if contact_id and contact_id > 0:
                    base += ' AND (sender_id = ? OR recipient_id = ?) '
                    params.extend([contact_id, contact_id])
                base += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
                params.extend([limit, offset])
                cursor.execute(base, tuple(params))
                rows = cursor.fetchall()
                return [{
                    'id': r[0], 'sender_id': r[1], 'recipient_id': r[2], 'file_name': r[3], 'file_type': r[4], 'file_size': r[5], 'encryption_used': bool(r[6]), 'thumbnail_path': r[7], 'created_at': r[8]
                } for r in rows]
        except Exception as e:
            print(f"Error listing media: {e}")
            return []

    def get_message_by_id(self, message_id: int) -> Optional[Dict]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT m.id, m.sender_id, m.recipient_id, m.content, m.encryption_used, m.created_at, u.username
                    FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.id = ?
                ''', (message_id,))
                r = cursor.fetchone()
                if not r:
                    return None
                return {
                    'id': r[0], 'sender_id': r[1], 'recipient_id': r[2], 'content': r[3], 'encryption_used': bool(r[4]), 'created_at': r[5], 'username': r[6]
                }
        except Exception as e:
            print(f"Error get_message_by_id: {e}")
            return None