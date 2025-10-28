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
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (sender_id) REFERENCES users (id),
                        FOREIGN KEY (recipient_id) REFERENCES users (id)
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
    
    def create_message(self, sender_id: int, recipient_id: int, content: str, 
                      encrypted_content: Optional[str] = None,
                      encryption_used: bool = False) -> Optional[int]:
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
                    INSERT INTO messages (sender_id, recipient_id, content, encrypted_content, encryption_used)
                    VALUES (?, ?, ?, ?, ?)
                ''', (sender_id, recipient_id, content, encrypted_content, encryption_used))
                
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
    
    def get_messages_between_users(self, user1_id: int, user2_id: int, limit: int = 50) -> List[Dict]:
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
                           m.encryption_used, m.status, m.delivered_at, m.read_at, m.created_at
                    FROM messages m
                    JOIN users u ON m.sender_id = u.id
                    WHERE (m.sender_id = ? AND m.recipient_id = ?) 
                       OR (m.sender_id = ? AND m.recipient_id = ?)
                    ORDER BY m.created_at DESC
                    LIMIT ?
                ''', (user1_id, user2_id, user2_id, user1_id, limit))
                
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
                        'created_at': row[9]
                    })
                
                return messages
                
        except Exception as e:
            print(f"Error getting messages between users: {e}")
            return []
    
    def create_file_share(self, sender_id: int, recipient_id: int, file_name: str,
                         file_type: str, file_size: int, encrypted_content: bytes,
                         encryption_used: bool = False) -> Optional[int]:
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
                                           file_size, encrypted_content, encryption_used)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (sender_id, recipient_id, file_name, file_type, file_size, 
                      encrypted_content, encryption_used))
                
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