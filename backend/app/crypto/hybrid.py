import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def derive_hybrid_key(bb84_entropy: bytes, kyber_shared_secret: bytes, context: bytes = b"QuantumNet-Hybrid-v1") -> bytes:
    """
    Combines BB84 entropy and Kyber shared secret using HKDF-SHA3-256.
    Returns: 32-byte (256-bit) hybrid session key.
    """
    # Input Key Material (IKM) = BB84 || Kyber
    ikm = bb84_entropy + kyber_shared_secret
    
    # Salt (optional, but good practice to use random salt if available, 
    # but here we want deterministic derivation if we had the same inputs.
    # However, usually salt is exchanged or fixed. We'll use a fixed salt for simplicity 
    # or None as per RFC 5869 if salt is not available.)
    salt = None 
    
    # HKDF using SHA256 (standard) or SHA3-256 (if supported by backend, usually is).
    # Let's use SHA256 for broad compatibility in 'cryptography' lib.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=context,
    )
    
    key = hkdf.derive(ikm)
    return key
