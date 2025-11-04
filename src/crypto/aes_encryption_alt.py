"""
AES-256 Encryption Implementation (Alternative using cryptography library)

This module provides AES-256 encryption and decryption functionality
using quantum-generated keys for secure communication.
"""

import os
import base64
import hashlib
from typing import Union, Optional

try:
    # Try pycryptodome first
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_LIB = "pycryptodome"
except ImportError:
    try:
        # Fallback to cryptography library
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.backends import default_backend
        import os as crypto_os
        CRYPTO_LIB = "cryptography"
    except ImportError:
        raise ImportError("Neither pycryptodome nor cryptography library is available. Please install one of them.")


class AESEncryption:
    """
    AES-256 encryption class for secure communication.
    
    This class provides AES-256 encryption and decryption using
    quantum-generated keys with proper padding and initialization vectors.
    """
    
    def __init__(self, key_size: int = 32):
        """
        Initialize AES encryption.
        
        Args:
            key_size: Key size in bytes (32 for AES-256)
        """
        self.key_size = key_size
        self.block_size = 16  # AES block size is always 16 bytes
        
    def generate_iv(self) -> bytes:
        """
        Generate a random initialization vector.
        
        Returns:
            Random IV bytes
        """
        if CRYPTO_LIB == "pycryptodome":
            return get_random_bytes(self.block_size)
        else:
            return crypto_os.urandom(self.block_size)
    
    def derive_key(self, quantum_key: Union[str, bytes, list]) -> bytes:
        """
        Derive a proper AES key from quantum key material.
        
        Args:
            quantum_key: Quantum key material (string, bytes, or list of bits)
            
        Returns:
            Derived AES key bytes
        """
        if isinstance(quantum_key, list):
            # Convert list of bits to binary string
            binary_string = ''.join(map(str, quantum_key))
            quantum_key = binary_string.encode('utf-8')
        elif isinstance(quantum_key, str):
            quantum_key = quantum_key.encode('utf-8')
        
        # Use SHA-256 to derive a proper key
        derived_key = hashlib.sha256(quantum_key).digest()
        
        # Ensure key is the correct size
        if len(derived_key) > self.key_size:
            derived_key = derived_key[:self.key_size]
        elif len(derived_key) < self.key_size:
            # Pad with zeros if needed
            derived_key = derived_key.ljust(self.key_size, b'\x00')
        
        return derived_key
    
    def encrypt(self, plaintext: Union[str, bytes], quantum_key: Union[str, bytes, list]) -> dict:
        """
        Encrypt plaintext using AES-256 with quantum key.
        
        Args:
            plaintext: Text or bytes to encrypt
            quantum_key: Quantum key material
            
        Returns:
            Dictionary containing encrypted data, IV, and metadata
        """
        try:
            # Convert plaintext to bytes
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            
            # Derive encryption key
            key = self.derive_key(quantum_key)
            
            # Generate random IV
            iv = self.generate_iv()
            
            if CRYPTO_LIB == "pycryptodome":
                # Use pycryptodome
                cipher = AES.new(key, AES.MODE_CBC, iv)
                padded_data = pad(plaintext, self.block_size)
                encrypted_data = cipher.encrypt(padded_data)
            else:
                # Use cryptography library
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(plaintext)
                padded_data += padder.finalize()
                
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Encode for storage/transmission
            encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
            iv_b64 = base64.b64encode(iv).decode('utf-8')
            
            return {
                'encrypted_data': encrypted_b64,
                'iv': iv_b64,
                'key_size': self.key_size,
                'block_size': self.block_size,
                'success': True
            }
            
        except Exception as e:
            return {
                'encrypted_data': None,
                'iv': None,
                'error': str(e),
                'success': False
            }
    
    def decrypt(self, encrypted_data: str, iv: str, quantum_key: Union[str, bytes, list]) -> dict:
        """
        Decrypt encrypted data using AES-256 with quantum key.
        
        Args:
            encrypted_data: Base64 encoded encrypted data
            iv: Base64 encoded initialization vector
            quantum_key: Quantum key material
            
        Returns:
            Dictionary containing decrypted data and metadata
        """
        try:
            # Decode base64 data
            encrypted_bytes = base64.b64decode(encrypted_data)
            iv_bytes = base64.b64decode(iv)
            
            # Derive decryption key
            key = self.derive_key(quantum_key)
            
            if CRYPTO_LIB == "pycryptodome":
                # Use pycryptodome
                cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
                decrypted_padded = cipher.decrypt(encrypted_bytes)
                decrypted_data = unpad(decrypted_padded, self.block_size)
            else:
                # Use cryptography library
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv_bytes), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()
                
                unpadder = padding.PKCS7(128).unpadder()
                decrypted_data = unpadder.update(decrypted_padded)
                decrypted_data += unpadder.finalize()
            
            # Try to decode as UTF-8 string
            try:
                decrypted_text = decrypted_data.decode('utf-8')
                return {
                    'decrypted_data': decrypted_text,
                    'data_type': 'string',
                    'success': True
                }
            except UnicodeDecodeError:
                return {
                    'decrypted_data': decrypted_data,
                    'data_type': 'bytes',
                    'success': True
                }
            
        except Exception as e:
            return {
                'decrypted_data': None,
                'error': str(e),
                'success': False
            }
    
    def get_key_info(self, quantum_key: Union[str, bytes, list]) -> dict:
        """
        Get information about a quantum key.
        
        Args:
            quantum_key: Quantum key material
            
        Returns:
            Dictionary containing key information
        """
        try:
            derived_key = self.derive_key(quantum_key)
            
            return {
                'original_type': type(quantum_key).__name__,
                'original_length': len(str(quantum_key)),
                'derived_key_length': len(derived_key),
                'key_size_bits': len(derived_key) * 8,
                'key_hex': derived_key.hex(),
                'key_entropy': self._calculate_key_entropy(derived_key),
                'crypto_library': CRYPTO_LIB
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _calculate_key_entropy(self, key: bytes) -> float:
        """
        Calculate the entropy of a key.
        
        Args:
            key: Key bytes
            
        Returns:
            Key entropy in bits
        """
        if not key:
            return 0.0
        
        # Count byte frequencies
        byte_counts = {}
        for byte in key:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        total_bytes = len(key)
        for count in byte_counts.values():
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * (probability.bit_length() - 1) if probability > 0 else 0
        
        return entropy
