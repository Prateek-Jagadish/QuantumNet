"""
PostgreSQL Database Manager for QuantumNet

This module mirrors the SQLite-based DatabaseManager API using psycopg2.
Select this manager when DATABASE_URL is provided.
"""

import os
import json
from typing import Dict, List, Optional
from datetime import datetime

import psycopg2
import psycopg2.extras


class PostgresDatabaseManager:
    """Database manager backed by PostgreSQL using psycopg2."""

    def __init__(self, database_url: str):
        self.database_url = database_url

    def _conn(self):
        return psycopg2.connect(self.database_url)

    def create_user(self, username: str, email: str, password_hash_or_plain: str) -> Optional[int]:
        try:
            # Accept plain hash (for parity with sqlite impl which hashes prior)
            password_hash = password_hash_or_plain
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO users (username, email, password_hash)
                    VALUES (%s, %s, %s)
                    RETURNING id
                    """,
                    (username, email, password_hash),
                )
                row = cur.fetchone()
                return row[0] if row else None
        except psycopg2.Error:
            return None

    def authenticate_user(self, username: str, password_hash: str) -> Optional[Dict]:
        try:
            with self._conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(
                    """
                    SELECT id, username, email, created_at, last_login
                    FROM users
                    WHERE username = %s AND password_hash = %s AND is_active = TRUE
                    """,
                    (username, password_hash),
                )
                row = cur.fetchone()
                if not row:
                    return None
                cur.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s", (row["id"],))
                return {
                    "id": row["id"],
                    "username": row["username"],
                    "email": row["email"],
                    "created_at": row["created_at"],
                    "last_login": row["last_login"],
                }
        except psycopg2.Error:
            return None

    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        try:
            with self._conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(
                    """
                    SELECT id, username, email, created_at, last_login, profile_photo_path
                    FROM users WHERE id = %s AND is_active = TRUE
                    """,
                    (user_id,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                return dict(row)
        except psycopg2.Error:
            return None

    def get_user_by_username(self, username: str) -> Optional[Dict]:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM users WHERE username = %s AND is_active = TRUE",
                    (username,),
                )
                row = cur.fetchone()
                return {"id": row[0]} if row else None
        except psycopg2.Error:
            return None

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM users WHERE email = %s AND is_active = TRUE",
                    (email,),
                )
                row = cur.fetchone()
                return {"id": row[0]} if row else None
        except psycopg2.Error:
            return None

    def search_users(self, query: str, limit: int = 10) -> List[Dict]:
        try:
            like = f"%{query.lower()}%"
            with self._conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(
                    """
                    SELECT id, username, email, last_seen, is_online
                    FROM users
                    WHERE is_active = TRUE AND (lower(username) LIKE %s OR lower(email) LIKE %s)
                    ORDER BY username ASC
                    LIMIT %s
                    """,
                    (like, like, limit),
                )
                return [dict(r) for r in cur.fetchall()]
        except psycopg2.Error:
            return []

    def update_user_profile(self, user_id: int, bio: Optional[str], phone: Optional[str]) -> bool:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute("UPDATE users SET bio = %s, phone = %s WHERE id = %s", (bio, phone, user_id))
            return True
        except psycopg2.Error:
            return False

    def update_profile_photo_path(self, user_id: int, path: str) -> bool:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute("UPDATE users SET profile_photo_path = %s WHERE id = %s", (path, user_id))
            return True
        except psycopg2.Error:
            return False

    def create_message(
        self,
        sender_id: int,
        recipient_id: int,
        content: str,
        encrypted_content: Optional[str] = None,
        encryption_used: bool = False,
        reply_to: Optional[int] = None,
    ) -> Optional[int]:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO messages (sender_id, recipient_id, content, encrypted_content, encryption_used, reply_to)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (sender_id, recipient_id, content, encrypted_content, encryption_used, reply_to),
                )
                row = cur.fetchone()
                return row[0] if row else None
        except psycopg2.Error:
            return None

    def get_recent_messages(self, limit: int = 50) -> List[Dict]:
        try:
            with self._conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(
                    """
                    SELECT m.id, m.sender_id, u.username, m.content, m.encryption_used, m.created_at
                    FROM messages m
                    JOIN users u ON m.sender_id = u.id
                    ORDER BY m.created_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                return [dict(r) for r in cur.fetchall()]
        except psycopg2.Error:
            return []

    def get_messages_between_users(self, user1_id: int, user2_id: int, limit: int = 50) -> List[Dict]:
        try:
            with self._conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(
                    """
                    SELECT m.id, m.sender_id, m.recipient_id, u.username, m.content,
                           m.encryption_used, m.status, m.delivered_at, m.read_at, m.created_at
                    FROM messages m
                    JOIN users u ON m.sender_id = u.id
                    WHERE (m.sender_id = %s AND m.recipient_id = %s)
                       OR (m.sender_id = %s AND m.recipient_id = %s)
                    ORDER BY m.created_at DESC
                    LIMIT %s
                    """,
                    (user1_id, user2_id, user2_id, user1_id, limit),
                )
                return [dict(r) for r in cur.fetchall()]
        except psycopg2.Error:
            return []

    def update_message_status(self, message_id: int, status: str) -> bool:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                if status == "delivered":
                    cur.execute(
                        "UPDATE messages SET status = 'delivered', delivered_at = CURRENT_TIMESTAMP WHERE id = %s",
                        (message_id,),
                    )
                elif status == "read":
                    cur.execute(
                        "UPDATE messages SET status = 'read', read_at = CURRENT_TIMESTAMP WHERE id = %s",
                        (message_id,),
                    )
            return True
        except psycopg2.Error:
            return False

    def react_to_message(self, message_id: int, emoji: str) -> bool:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute("SELECT reactions FROM messages WHERE id = %s", (message_id,))
                row = cur.fetchone()
                reactions = []
                if row and row[0]:
                    try:
                        reactions = row[0]
                    except Exception:
                        reactions = []
                reactions.append(emoji)
                cur.execute("UPDATE messages SET reactions = %s WHERE id = %s", (json.dumps(reactions), message_id))
            return True
        except psycopg2.Error:
            return False

    def mark_message_deleted(self, message_id: int, for_user_id: int) -> bool:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute("SELECT sender_id, recipient_id FROM messages WHERE id = %s", (message_id,))
                row = cur.fetchone()
                if not row:
                    return False
                if row[0] == for_user_id:
                    cur.execute("UPDATE messages SET is_deleted_sender = TRUE WHERE id = %s", (message_id,))
                elif row[1] == for_user_id:
                    cur.execute("UPDATE messages SET is_deleted_recipient = TRUE WHERE id = %s", (message_id,))
                else:
                    return False
            return True
        except psycopg2.Error:
            return False

    def delete_message_for_everyone(self, message_id: int) -> bool:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute("UPDATE messages SET content = '', encrypted_content = NULL, status = 'deleted' WHERE id = %s", (message_id,))
            return True
        except psycopg2.Error:
            return False

    def create_file_share(
        self,
        sender_id: int,
        recipient_id: int,
        file_name: str,
        file_type: str,
        file_size: int,
        encrypted_content: bytes,
        encryption_used: bool = False,
        thumbnail_path: Optional[str] = None,
    ) -> Optional[int]:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO file_shares (sender_id, recipient_id, file_name, file_type, file_size, encrypted_content, encryption_used, thumbnail_path)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        sender_id,
                        recipient_id,
                        file_name,
                        file_type,
                        file_size,
                        psycopg2.Binary(encrypted_content),
                        encryption_used,
                        thumbnail_path,
                    ),
                )
                row = cur.fetchone()
                return row[0] if row else None
        except psycopg2.Error:
            return None

    def get_file_share(self, file_id: int) -> Optional[Dict]:
        try:
            with self._conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(
                    """
                    SELECT id, sender_id, recipient_id, file_name, file_type, file_size, encrypted_content, encryption_used, created_at
                    FROM file_shares WHERE id = %s
                    """,
                    (file_id,),
                )
                row = cur.fetchone()
                return dict(row) if row else None
        except psycopg2.Error:
            return None

    def get_user_message_count(self, user_id: int) -> int:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM messages WHERE sender_id = %s OR recipient_id = %s",
                    (user_id, user_id),
                )
                return cur.fetchone()[0]
        except psycopg2.Error:
            return 0

    def create_security_event(
        self,
        user_id: int,
        event_type: str,
        description: str,
        threat_level: str = "LOW",
        metadata: Optional[Dict] = None,
    ) -> Optional[int]:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO security_events (user_id, event_type, description, threat_level, metadata)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (user_id, event_type, description, threat_level, json.dumps(metadata) if metadata else None),
                )
                row = cur.fetchone()
                return row[0] if row else None
        except psycopg2.Error:
            return None

    def get_user_security_events(self, user_id: int, limit: int = 50) -> List[Dict]:
        try:
            with self._conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(
                    """
                    SELECT id, event_type, description, threat_level, ml_prediction, confidence, metadata, created_at
                    FROM security_events WHERE user_id = %s ORDER BY created_at DESC LIMIT %s
                    """,
                    (user_id, limit),
                )
                rows = cur.fetchall()
                events = []
                for r in rows:
                    md = r["metadata"] if r["metadata"] else {}
                    if isinstance(md, str):
                        try:
                            md = json.loads(md)
                        except Exception:
                            md = {}
                    ev = dict(r)
                    ev["metadata"] = md
                    events.append(ev)
                return events
        except psycopg2.Error:
            return []

    def get_user_security_events_count(self, user_id: int) -> int:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM security_events WHERE user_id = %s", (user_id,))
                return cur.fetchone()[0]
        except psycopg2.Error:
            return 0

    def update_user_presence(self, user_id: int, is_online: bool = True) -> bool:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET is_online = %s, last_seen = CURRENT_TIMESTAMP WHERE id = %s",
                    (is_online, user_id),
                )
            return True
        except psycopg2.Error:
            return False

    def get_online_users(self) -> List[Dict]:
        try:
            with self._conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(
                    "SELECT id, username, last_seen, is_online FROM users WHERE is_online = TRUE AND is_active = TRUE ORDER BY last_seen DESC"
                )
                return [dict(r) for r in cur.fetchall()]
        except psycopg2.Error:
            return []

    def create_device(
        self,
        user_id: int,
        device_id: str,
        device_name: str = None,
        browser: str = None,
        os: str = None,
        ip_address: str = None,
    ) -> Optional[int]:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM devices WHERE user_id = %s AND device_id = %s",
                    (user_id, device_id),
                )
                row = cur.fetchone()
                if row:
                    cur.execute(
                        "UPDATE devices SET last_active = CURRENT_TIMESTAMP, is_active = TRUE WHERE id = %s",
                        (row[0],),
                    )
                    return row[0]
                cur.execute(
                    """
                    INSERT INTO devices (user_id, device_id, device_name, browser, os, ip_address)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (user_id, device_id, device_name, browser, os, ip_address),
                )
                row = cur.fetchone()
                return row[0] if row else None
        except psycopg2.Error:
            return None

    def search_messages(self, user_id: int, query: str, limit: int = 50) -> List[Dict]:
        try:
            like = f"%{query}%"
            with self._conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(
                    """
                    SELECT m.id, m.sender_id, m.recipient_id, m.content, m.created_at
                    FROM messages m
                    WHERE (m.sender_id = %s OR m.recipient_id = %s) AND m.content LIKE %s
                    ORDER BY m.created_at DESC
                    LIMIT %s
                    """,
                    (user_id, user_id, like, limit),
                )
                return [dict(r) for r in cur.fetchall()]
        except psycopg2.Error:
            return []

    def add_contact(self, user_id: int, contact_id: int, status: str = "normal") -> bool:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO contacts (user_id, contact_id, status)
                    VALUES (%s, %s, %s)
                    ON CONFLICT(user_id, contact_id) DO UPDATE SET status=EXCLUDED.status
                    """,
                    (user_id, contact_id, status),
                )
            return True
        except psycopg2.Error:
            return False

    def remove_contact(self, user_id: int, contact_id: int) -> bool:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute("DELETE FROM contacts WHERE user_id = %s AND contact_id = %s", (user_id, contact_id))
            return True
        except psycopg2.Error:
            return False

    def set_contact_status(self, user_id: int, contact_id: int, status: str) -> bool:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "UPDATE contacts SET status = %s WHERE user_id = %s AND contact_id = %s",
                    (status, user_id, contact_id),
                )
                return cur.rowcount > 0
        except psycopg2.Error:
            return False

    def list_contacts(self, user_id: int) -> List[Dict]:
        try:
            with self._conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(
                    """
                    SELECT c.contact_id AS id, u.username, u.email, c.status, u.is_online, u.last_seen,
                           COALESCE(unread.unread_count, 0) AS unread_count
                    FROM contacts c
                    JOIN users u ON c.contact_id = u.id
                    LEFT JOIN (
                        SELECT sender_id, COUNT(*) AS unread_count
                        FROM messages
                        WHERE recipient_id = %s AND status <> 'read'
                        GROUP BY sender_id
                    ) AS unread ON unread.sender_id = c.contact_id
                    WHERE c.user_id = %s
                    ORDER BY (c.status = 'favorite') DESC, u.username ASC
                    """,
                    (user_id, user_id),
                )
                return [dict(r) for r in cur.fetchall()]
        except psycopg2.Error:
            return []

    def get_unread_count(self, user_id: int, from_contact_id: int) -> int:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM messages WHERE recipient_id = %s AND sender_id = %s AND status <> 'read'",
                    (user_id, from_contact_id),
                )
                return cur.fetchone()[0]
        except psycopg2.Error:
            return 0


