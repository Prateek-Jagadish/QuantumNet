import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_message(key: bytes, plaintext: bytes, aad: bytes = None) -> tuple[bytes, bytes, bytes]:
    """
    Encrypts a message using AES-256-GCM.
    Returns: (nonce, ciphertext, auth_tag)
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    
    # encrypt() returns ciphertext + tag appended
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, aad)
    
    # Split ciphertext and tag (tag is last 16 bytes)
    ciphertext = ct_and_tag[:-16]
    auth_tag = ct_and_tag[-16:]
    
    return nonce, ciphertext, auth_tag

def decrypt_message(key: bytes, nonce: bytes, ciphertext: bytes, auth_tag: bytes, aad: bytes = None) -> bytes:
    """
    Decrypts a message using AES-256-GCM.
    Returns: plaintext
    """
    aesgcm = AESGCM(key)
    
    # decrypt() expects ciphertext + tag appended
    ct_and_tag = ciphertext + auth_tag
    
    return aesgcm.decrypt(nonce, ct_and_tag, aad)
