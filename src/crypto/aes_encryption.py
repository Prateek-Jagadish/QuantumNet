"""
AES-256 Encryption Implementation

This module provides AES-256 encryption and decryption functionality
using quantum-generated keys for secure communication.
"""

import os
import base64
import hashlib
from typing import Union, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os as crypto_os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM



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
            
            # Create AES cipher using cryptography library
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

    def encrypt_bytes(self, plaintext_bytes: bytes, quantum_key: Union[str, bytes, list]) -> dict:
        """Encrypt raw bytes using AES-GCM. Returns ciphertext bytes and iv bytes."""
        try:
            key = self.derive_key(quantum_key)
            # AESGCM requires 16/24/32-byte key; we already have 32
            aesgcm = AESGCM(key)
            iv = crypto_os.urandom(12)
            ciphertext = aesgcm.encrypt(iv, plaintext_bytes, None)
            return { 'success': True, 'ciphertext': ciphertext, 'iv': iv }
        except Exception as e:
            return { 'success': False, 'error': str(e) }

    def decrypt_bytes(self, ciphertext: bytes, iv: bytes, quantum_key: Union[str, bytes, list]) -> dict:
        """Decrypt raw bytes using AES-GCM."""
        try:
            key = self.derive_key(quantum_key)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
            return { 'success': True, 'plaintext': plaintext }
        except Exception as e:
            return { 'success': False, 'error': str(e) }
    
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
            
            # Create AES cipher using cryptography library
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv_bytes), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()
            
            # Remove padding
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
    
    def encrypt_file(self, file_path: str, quantum_key: Union[str, bytes, list], output_path: Optional[str] = None) -> dict:
        """
        Encrypt a file using AES-256.
        
        Args:
            file_path: Path to file to encrypt
            quantum_key: Quantum key material
            output_path: Output path for encrypted file (optional)
            
        Returns:
            Dictionary containing encryption result
        """
        try:
            if not os.path.exists(file_path):
                return {'success': False, 'error': 'File not found'}
            
            # Read file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Encrypt file data
            result = self.encrypt(file_data, quantum_key)
            
            if not result['success']:
                return result
            
            # Determine output path
            if output_path is None:
                output_path = file_path + '.encrypted'
            
            # Write encrypted data to file
            with open(output_path, 'w') as f:
                f.write(result['encrypted_data'])
                f.write('\n')
                f.write(result['iv'])
            
            return {
                'success': True,
                'output_path': output_path,
                'original_size': len(file_data),
                'encrypted_size': len(result['encrypted_data'])
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def decrypt_file(self, encrypted_file_path: str, quantum_key: Union[str, bytes, list], output_path: Optional[str] = None) -> dict:
        """
        Decrypt an encrypted file.
        
        Args:
            encrypted_file_path: Path to encrypted file
            quantum_key: Quantum key material
            output_path: Output path for decrypted file (optional)
            
        Returns:
            Dictionary containing decryption result
        """
        try:
            if not os.path.exists(encrypted_file_path):
                return {'success': False, 'error': 'Encrypted file not found'}
            
            # Read encrypted file
            with open(encrypted_file_path, 'r') as f:
                lines = f.readlines()
            
            if len(lines) < 2:
                return {'success': False, 'error': 'Invalid encrypted file format'}
            
            encrypted_data = lines[0].strip()
            iv = lines[1].strip()
            
            # Decrypt data
            result = self.decrypt(encrypted_data, iv, quantum_key)
            
            if not result['success']:
                return result
            
            # Determine output path
            if output_path is None:
                if encrypted_file_path.endswith('.encrypted'):
                    output_path = encrypted_file_path[:-10]  # Remove .encrypted
                else:
                    output_path = encrypted_file_path + '.decrypted'
            
            # Write decrypted data to file
            with open(output_path, 'wb') as f:
                f.write(result['decrypted_data'])
            
            return {
                'success': True,
                'output_path': output_path,
                'decrypted_size': len(result['decrypted_data'])
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
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
                'key_entropy': self._calculate_key_entropy(derived_key)
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
            probability = count / total_bytes
            entropy -= probability * (probability.bit_length() - 1) if probability > 0 else 0
        
        return entropy
