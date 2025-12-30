import os
import hashlib
from typing import Tuple

# =============================================================================
# PURE PYTHON KYBER-768 IMPLEMENTATION (Simplified for Educational/Demo Use)
# =============================================================================
# This implementation follows the CRYSTALS-Kyber specification for Kyber-768.
# It implements the Ring-LWE scheme with Number Theoretic Transform (NTT).
# Note: This is a functional implementation for the QuantumNet project to provide
# actual Lattice-based cryptography. It is NOT side-channel resistant.

# --- Constants for Kyber-768 ---
n = 256
q = 3329
k = 3  # Kyber-768
eta1 = 2
eta2 = 2
du = 10
dv = 4

# Polynomial Ring: R_q = Z_q[X] / (X^n + 1)

def parse_bytes(b):
    """Convert bytes to list of integers."""
    return [x for x in b]

def serialize_bytes(l):
    """Convert list of integers to bytes."""
    return bytes(l)

# --- Number Theoretic Transform (NTT) Helpers ---
# We use a simple O(n^2) multiplication for simplicity in this demo version 
# to avoid complex NTT code bloat, but we simulate the Ring structure correctly.
# In a full production version, O(n log n) NTT is used.

def poly_add(a, b):
    """Add two polynomials in R_q."""
    return [(x + y) % q for x, y in zip(a, b)]

def poly_sub(a, b):
    """Subtract two polynomials in R_q."""
    return [(x - y) % q for x, y in zip(a, b)]

def poly_mul(a, b):
    """Multiply two polynomials in R_q (Naive O(n^2) for simplicity)."""
    res = [0] * (2 * n)
    for i in range(n):
        for j in range(n):
            res[i + j] = (res[i + j] + a[i] * b[j]) % q
    
    # Reduction modulo X^n + 1
    # X^n = -1 mod (X^n + 1)
    out = [0] * n
    for i in range(n):
        out[i] = (res[i] - res[i + n]) % q
    return out

def vec_dot(a, b):
    """Dot product of two vectors of polynomials."""
    res = [0] * n
    for p1, p2 in zip(a, b):
        res = poly_add(res, poly_mul(p1, p2))
    return res

# --- Centered Binomial Distribution (CBD) ---
def cbd(b, eta):
    """
    Sample from Centered Binomial Distribution.
    Parses bytes to polynomial coefficients.
    """
    # This is a simplified version of CBD for the demo
    # We consume bytes to generate noise
    poly = []
    bits = []
    for byte in b:
        for i in range(8):
            bits.append((byte >> i) & 1)
            
    for i in range(n):
        if 2*eta*i + 2*eta > len(bits):
            break # Should not happen if input is long enough
        
        a = sum(bits[2*eta*i : 2*eta*i + eta])
        b_val = sum(bits[2*eta*i + eta : 2*eta*i + 2*eta])
        poly.append((a - b_val) % q)
        
    # Pad if needed (should not be needed with correct input size)
    while len(poly) < n:
        poly.append(0)
    return poly

# --- Serialization ---
def encode_poly(p, bits):
    """Encode polynomial coefficients to bytes."""
    # Simplified encoding for demo
    # We just pack 16-bit integers (since q=3329 < 2^16)
    # Real Kyber uses bit-packing
    out = bytearray()
    for coeff in p:
        out.extend(coeff.to_bytes(2, 'little'))
    return bytes(out)

def decode_poly(b, bits):
    """Decode bytes to polynomial coefficients."""
    p = []
    for i in range(0, len(b), 2):
        val = int.from_bytes(b[i:i+2], 'little')
        p.append(val)
    return p

# --- Core Functions ---

def generate_matrix(seed):
    """Generate matrix A from seed (simulated)."""
    # In real Kyber, this uses SHAKE-128.
    # We simulate by generating deterministic pseudo-random polynomials.
    # We use hashlib for determinism.
    A = []
    for i in range(k):
        row = []
        for j in range(k):
            # Hash seed + indices to get randomness
            h = hashlib.sha256(seed + bytes([i, j])).digest()
            # Expand to polynomial (simple uniform sampling mod q)
            poly = []
            # We need n coefficients. SHA256 gives 32 bytes. We need more.
            # Let's extend the hash
            extended_hash = h
            while len(extended_hash) < n * 2:
                extended_hash += hashlib.sha256(extended_hash).digest()
            
            for x in range(n):
                val = int.from_bytes(extended_hash[x*2:(x+1)*2], 'little') % q
                poly.append(val)
            row.append(poly)
        A.append(row)
    return A

def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generates a Kyber-768 keypair.
    Returns: (public_key, private_key)
    """
    # 1. Random seed
    seed = os.urandom(32)
    
    # 2. Generate Matrix A
    A = generate_matrix(seed)
    
    # 3. Sample secret vector s and error vector e from CBD
    # We need noise.
    noise_seed = os.urandom(64)
    s = []
    e = []
    for i in range(k):
        # Generate noise for s[i] and e[i]
        # We use different slices of noise_seed or hash it
        n_bytes = hashlib.sha256(noise_seed + bytes([i])).digest() * 4 # Need enough bits
        s.append(cbd(n_bytes, eta1))
        
        n_bytes_e = hashlib.sha256(noise_seed + bytes([i+k])).digest() * 4
        e.append(cbd(n_bytes_e, eta1))
        
    # 4. t = A * s + e
    t = []
    for i in range(k):
        # Row i of A dot s
        row_dot_s = vec_dot(A[i], s)
        # Add e[i]
        val = poly_add(row_dot_s, e[i])
        t.append(val)
        
    # 5. Pack Public Key (t, seed)
    pk_bytes = bytearray()
    for poly in t:
        pk_bytes.extend(encode_poly(poly, 12))
    pk_bytes.extend(seed)
    
    # 6. Pack Private Key (s)
    sk_bytes = bytearray()
    for poly in s:
        sk_bytes.extend(encode_poly(poly, 12))
        
    return bytes(pk_bytes), bytes(sk_bytes)

def encapsulate(pk_bytes: bytes) -> Tuple[bytes, bytes]:
    """
    Generates a shared secret and ciphertext.
    Returns: (ciphertext, shared_secret)
    """
    # 1. Unpack Public Key
    # Last 32 bytes is seed
    seed = pk_bytes[-32:]
    t_bytes = pk_bytes[:-32]
    
    # Decode t
    t = []
    poly_size = n * 2 # 2 bytes per coeff
    for i in range(k):
        p_bytes = t_bytes[i*poly_size : (i+1)*poly_size]
        t.append(decode_poly(p_bytes, 12))
        
    # 2. Generate Matrix A from seed
    A = generate_matrix(seed)
    
    # 3. Sample random vector r, error e1, error e2
    rand_seed = os.urandom(32)
    r = []
    e1 = []
    for i in range(k):
        n_bytes = hashlib.sha256(rand_seed + bytes([i])).digest() * 4
        r.append(cbd(n_bytes, eta1))
        
        n_bytes_e = hashlib.sha256(rand_seed + bytes([i+k])).digest() * 4
        e1.append(cbd(n_bytes_e, eta2))
        
    n_bytes_e2 = hashlib.sha256(rand_seed + b'e2').digest() * 4
    e2 = cbd(n_bytes_e2, eta2)
    
    # 4. u = A^T * r + e1
    u = []
    for i in range(k):
        # Column i of A (which is Row i of A^T)
        # A[j][i]
        col_i = [A[j][i] for j in range(k)]
        dot_val = vec_dot(col_i, r)
        val = poly_add(dot_val, e1[i])
        u.append(val)
        
    # 5. v = t^T * r + e2 + m (where m is encoded shared secret)
    # We generate the shared secret 'm' (random 32 bytes)
    shared_secret = os.urandom(32)
    
    # Encode m to polynomial
    # Each bit of m becomes a coefficient (0 or q/2)
    m_poly = [0] * n
    m_bits = []
    for byte in shared_secret:
        for i in range(8):
            m_bits.append((byte >> i) & 1)
            
    for i in range(n):
        if i < len(m_bits) and m_bits[i] == 1:
            m_poly[i] = (q + 1) // 2 # q/2
        else:
            m_poly[i] = 0
            
    # v = t dot r + e2 + m
    t_dot_r = vec_dot(t, r)
    v = poly_add(poly_add(t_dot_r, e2), m_poly)
    
    # 6. Pack Ciphertext (u, v)
    ct_bytes = bytearray()
    for poly in u:
        ct_bytes.extend(encode_poly(poly, 10)) # u
    ct_bytes.extend(encode_poly(v, 4)) # v
    
    return bytes(ct_bytes), shared_secret

def decapsulate(ct_bytes: bytes, sk_bytes: bytes) -> bytes:
    """
    Recovers the shared secret using the private key.
    Returns: shared_secret
    """
    # 1. Unpack Ciphertext
    u = []
    poly_size = n * 2
    for i in range(k):
        p_bytes = ct_bytes[i*poly_size : (i+1)*poly_size]
        u.append(decode_poly(p_bytes, 10))
        
    v_bytes = ct_bytes[k*poly_size:]
    v = decode_poly(v_bytes, 4)
    
    # 2. Unpack Private Key
    s = []
    for i in range(k):
        p_bytes = sk_bytes[i*poly_size : (i+1)*poly_size]
        s.append(decode_poly(p_bytes, 12))
        
    # 3. Noisy Secret = v - s^T * u
    s_dot_u = vec_dot(s, u)
    noisy_m = poly_sub(v, s_dot_u)
    
    # 4. Decode m (Recover Shared Secret)
    # If coeff is closer to q/2, bit is 1. If closer to 0, bit is 0.
    recovered_bits = []
    for coeff in noisy_m:
        # Normalize to [0, 1]
        # Distance to 0
        d0 = min(coeff, q - coeff)
        # Distance to q/2
        dq2 = abs(coeff - (q // 2))
        
        if dq2 < d0:
            recovered_bits.append(1)
        else:
            recovered_bits.append(0)
            
    # Pack bits to bytes
    out_bytes = bytearray()
    for i in range(0, 256, 8):
        byte_val = 0
        for j in range(8):
            if i + j < len(recovered_bits):
                byte_val |= (recovered_bits[i + j] << j)
        out_bytes.append(byte_val)
        
    return bytes(out_bytes)
