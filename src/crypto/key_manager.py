"""
Key Manager for Quantum Key Distribution

This module provides key management functionality including key storage,
expiry, persistence, and secure key distribution.
"""

import os
import json
import time
import hashlib
from typing import Dict, List, Optional, Union
from datetime import datetime, timedelta
import threading


class KeyManager:
    """
    KeyManager class for managing quantum-generated keys.
    
    This class handles key storage, expiry, persistence, and provides
    secure key distribution for encrypted communication.
    """
    
    def __init__(self, storage_path: str = "data/keys", default_expiry_hours: int = 24):
        """
        Initialize the key manager.
        
        Args:
            storage_path: Path to store key files
            default_expiry_hours: Default key expiry time in hours
        """
        self.storage_path = storage_path
        self.default_expiry_hours = default_expiry_hours
        self.keys = {}  # In-memory key storage
        self.key_metadata = {}  # Key metadata storage
        self.lock = threading.Lock()  # Thread safety
        
        # Ensure storage directory exists
        os.makedirs(storage_path, exist_ok=True)
        
        # Load existing keys
        self._load_keys()
    
    def generate_key_id(self, user_id: str, session_id: str) -> str:
        """
        Generate a unique key ID.
        
        Args:
            user_id: User identifier
            session_id: Session identifier
            
        Returns:
            Unique key ID
        """
        timestamp = str(int(time.time()))
        key_data = f"{user_id}:{session_id}:{timestamp}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]
    
    def store_key(self, key_id: str, quantum_key: Union[str, bytes, list], 
                  user_id: str, session_id: str, expiry_hours: Optional[int] = None) -> bool:
        """
        Store a quantum key with metadata.
        
        Args:
            key_id: Unique key identifier
            quantum_key: Quantum key material
            user_id: User identifier
            session_id: Session identifier
            expiry_hours: Key expiry time in hours (optional)
            
        Returns:
            True if successful
        """
        try:
            with self.lock:
                # Convert key to string format
                if isinstance(quantum_key, list):
                    key_string = ''.join(map(str, quantum_key))
                elif isinstance(quantum_key, bytes):
                    key_string = quantum_key.decode('utf-8')
                else:
                    key_string = str(quantum_key)
                
                # Calculate expiry time
                expiry_hours = expiry_hours or self.default_expiry_hours
                expiry_time = datetime.now() + timedelta(hours=expiry_hours)
                
                # Store key and metadata
                self.keys[key_id] = key_string
                self.key_metadata[key_id] = {
                    'user_id': user_id,
                    'session_id': session_id,
                    'created_at': datetime.now().isoformat(),
                    'expires_at': expiry_time.isoformat(),
                    'expiry_hours': expiry_hours,
                    'key_length': len(key_string),
                    'last_used': None,
                    'usage_count': 0
                }
                
                # Persist to disk
                self._save_key_to_disk(key_id)
                
                return True
                
        except Exception as e:
            print(f"Error storing key {key_id}: {e}")
            return False
    
    def get_key(self, key_id: str) -> Optional[str]:
        """
        Retrieve a quantum key by ID.
        
        Args:
            key_id: Key identifier
            
        Returns:
            Quantum key string or None if not found/expired
        """
        try:
            with self.lock:
                if key_id not in self.keys:
                    return None
                
                # Check if key is expired
                if self._is_key_expired(key_id):
                    self._remove_key(key_id)
                    return None
                
                # Update usage statistics
                self.key_metadata[key_id]['last_used'] = datetime.now().isoformat()
                self.key_metadata[key_id]['usage_count'] += 1
                
                return self.keys[key_id]
                
        except Exception as e:
            print(f"Error retrieving key {key_id}: {e}")
            return None
    
    def get_key_metadata(self, key_id: str) -> Optional[Dict]:
        """
        Get metadata for a key.
        
        Args:
            key_id: Key identifier
            
        Returns:
            Key metadata dictionary or None
        """
        with self.lock:
            return self.key_metadata.get(key_id)
    
    def is_key_valid(self, key_id: str) -> bool:
        """
        Check if a key is valid and not expired.
        
        Args:
            key_id: Key identifier
            
        Returns:
            True if key is valid
        """
        with self.lock:
            if key_id not in self.keys:
                return False
            
            return not self._is_key_expired(key_id)
    
    def extend_key_expiry(self, key_id: str, additional_hours: int) -> bool:
        """
        Extend the expiry time of a key.
        
        Args:
            key_id: Key identifier
            additional_hours: Additional hours to extend
            
        Returns:
            True if successful
        """
        try:
            with self.lock:
                if key_id not in self.key_metadata:
                    return False
                
                current_expiry = datetime.fromisoformat(self.key_metadata[key_id]['expires_at'])
                new_expiry = current_expiry + timedelta(hours=additional_hours)
                
                self.key_metadata[key_id]['expires_at'] = new_expiry.isoformat()
                self.key_metadata[key_id]['expiry_hours'] += additional_hours
                
                # Persist changes
                self._save_key_to_disk(key_id)
                
                return True
                
        except Exception as e:
            print(f"Error extending key expiry {key_id}: {e}")
            return False
    
    def remove_key(self, key_id: str) -> bool:
        """
        Remove a key from storage.
        
        Args:
            key_id: Key identifier
            
        Returns:
            True if successful
        """
        try:
            with self.lock:
                self._remove_key(key_id)
                return True
                
        except Exception as e:
            print(f"Error removing key {key_id}: {e}")
            return False
    
    def cleanup_expired_keys(self) -> int:
        """
        Remove all expired keys.
        
        Returns:
            Number of keys removed
        """
        removed_count = 0
        
        with self.lock:
            expired_keys = [key_id for key_id in self.keys.keys() if self._is_key_expired(key_id)]
            
            for key_id in expired_keys:
                self._remove_key(key_id)
                removed_count += 1
        
        return removed_count
    
    def get_user_keys(self, user_id: str) -> List[str]:
        """
        Get all key IDs for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of key IDs
        """
        with self.lock:
            user_keys = []
            for key_id, metadata in self.key_metadata.items():
                if metadata['user_id'] == user_id and not self._is_key_expired(key_id):
                    user_keys.append(key_id)
            
            return user_keys
    
    def get_session_keys(self, session_id: str) -> List[str]:
        """
        Get all key IDs for a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            List of key IDs
        """
        with self.lock:
            session_keys = []
            for key_id, metadata in self.key_metadata.items():
                if metadata['session_id'] == session_id and not self._is_key_expired(key_id):
                    session_keys.append(key_id)
            
            return session_keys
    
    def get_key_statistics(self) -> Dict:
        """
        Get statistics about stored keys.
        
        Returns:
            Dictionary containing key statistics
        """
        with self.lock:
            total_keys = len(self.keys)
            expired_keys = sum(1 for key_id in self.keys.keys() if self._is_key_expired(key_id))
            valid_keys = total_keys - expired_keys
            
            # Calculate average key length
            if self.keys:
                avg_key_length = sum(len(key) for key in self.keys.values()) / len(self.keys)
            else:
                avg_key_length = 0
            
            # Calculate total usage
            total_usage = sum(metadata.get('usage_count', 0) for metadata in self.key_metadata.values())
            
            return {
                'total_keys': total_keys,
                'valid_keys': valid_keys,
                'expired_keys': expired_keys,
                'average_key_length': avg_key_length,
                'total_usage_count': total_usage,
                'storage_path': self.storage_path
            }
    
    def _is_key_expired(self, key_id: str) -> bool:
        """Check if a key is expired."""
        if key_id not in self.key_metadata:
            return True
        
        expiry_time = datetime.fromisoformat(self.key_metadata[key_id]['expires_at'])
        return datetime.now() > expiry_time
    
    def _remove_key(self, key_id: str):
        """Remove a key from memory and disk."""
        if key_id in self.keys:
            del self.keys[key_id]
        
        if key_id in self.key_metadata:
            del self.key_metadata[key_id]
        
        # Remove from disk
        key_file = os.path.join(self.storage_path, f"{key_id}.json")
        if os.path.exists(key_file):
            os.remove(key_file)
    
    def _save_key_to_disk(self, key_id: str):
        """Save a key and its metadata to disk."""
        key_file = os.path.join(self.storage_path, f"{key_id}.json")
        
        key_data = {
            'key_id': key_id,
            'key': self.keys[key_id],
            'metadata': self.key_metadata[key_id]
        }
        
        with open(key_file, 'w') as f:
            json.dump(key_data, f, indent=2)
    
    def _load_keys(self):
        """Load keys from disk storage."""
        try:
            for filename in os.listdir(self.storage_path):
                if filename.endswith('.json'):
                    key_file = os.path.join(self.storage_path, filename)
                    
                    with open(key_file, 'r') as f:
                        key_data = json.load(f)
                    
                    key_id = key_data['key_id']
                    self.keys[key_id] = key_data['key']
                    self.key_metadata[key_id] = key_data['metadata']
                    
                    # Remove expired keys during loading
                    if self._is_key_expired(key_id):
                        self._remove_key(key_id)
                        
        except Exception as e:
            print(f"Error loading keys: {e}")
    
    def export_keys(self, output_file: str) -> bool:
        """
        Export all keys to a file.
        
        Args:
            output_file: Output file path
            
        Returns:
            True if successful
        """
        try:
            with self.lock:
                export_data = {
                    'keys': self.keys,
                    'metadata': self.key_metadata,
                    'export_time': datetime.now().isoformat()
                }
                
                with open(output_file, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                return True
                
        except Exception as e:
            print(f"Error exporting keys: {e}")
            return False
    
    def import_keys(self, input_file: str) -> bool:
        """
        Import keys from a file.
        
        Args:
            input_file: Input file path
            
        Returns:
            True if successful
        """
        try:
            with open(input_file, 'r') as f:
                import_data = json.load(f)
            
            with self.lock:
                self.keys.update(import_data['keys'])
                self.key_metadata.update(import_data['metadata'])
                
                # Save all imported keys to disk
                for key_id in import_data['keys'].keys():
                    self._save_key_to_disk(key_id)
            
            return True
            
        except Exception as e:
            print(f"Error importing keys: {e}")
            return False
