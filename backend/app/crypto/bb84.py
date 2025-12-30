import os
import random
from typing import Tuple, List

# BB84 SIMULATION
# In a real QKD system, this happens over a quantum channel (fiber/free-space).
# Here we simulate the "Sifting" and "Error Estimation" phases.

def generate_quantum_state(length: int = 512) -> Tuple[bytes, float]:
    """
    Simulates the generation of a raw key via BB84.
    Returns: (entropy_bytes, qber_value)
    """
    # 1. Alice chooses random bits and bases
    alice_bits = [random.choice([0, 1]) for _ in range(length)]
    alice_bases = [random.choice(['+', 'x']) for _ in range(length)]
    
    # 2. Bob chooses random bases
    bob_bases = [random.choice(['+', 'x']) for _ in range(length)]
    
    # 3. Sifting: Keep bits where bases match
    sifted_bits = []
    for i in range(length):
        if alice_bases[i] == bob_bases[i]:
            sifted_bits.append(alice_bits[i])
            
    # 4. Error Estimation (Simulate Noise/Eavesdropping)
    # Base QBER is low (e.g., 1-2%)
    # If we want to simulate an attack, we increase it.
    # For now, random fluctuation between 0.5% and 3.0%
    qber = random.uniform(0.005, 0.030)
    
    # If QBER > 11%, the key is discarded (theoretical limit).
    # We return the QBER for the dashboard.
    
    # 5. Privacy Amplification (Simplified)
    # We take the sifted bits and hash them or just take a subset.
    # For simulation, we just pack the bits into bytes.
    
    # Ensure we have enough bits for 256-bit key (32 bytes)
    # If not, we pad (in simulation only).
    
    # Convert bits to bytes
    # This is the "Quantum Entropy"
    entropy_int = 0
    for bit in sifted_bits:
        entropy_int = (entropy_int << 1) | bit
        
    # Length in bytes
    num_bytes = (len(sifted_bits) + 7) // 8
    entropy_bytes = entropy_int.to_bytes(num_bytes, byteorder='big')
    
    # Truncate or Pad to 32 bytes for consistency in this demo
    if len(entropy_bytes) > 32:
        entropy_bytes = entropy_bytes[:32]
    else:
        entropy_bytes = entropy_bytes.ljust(32, b'\0')
        
    return entropy_bytes, qber
