"""
Alice - Quantum Key Distribution Sender

Alice is the sender in the BB84 protocol. She generates random bits,
chooses random bases, prepares quantum states, and sends them to Bob.
"""

import random
import numpy as np
from typing import List, Tuple, Optional


class Alice:
    """
    Alice class implementing the sender side of BB84 protocol.
    
    Alice generates random bits, chooses random bases, prepares quantum states,
    and sends them through the quantum channel to Bob.
    """
    
    def __init__(self, name: str = "Alice"):
        """
        Initialize Alice.
        
        Args:
            name: Name identifier for Alice
        """
        self.name = name
        self.bits = []  # Random bits to send
        self.bases = []  # Bases chosen for each bit
        self.quantum_states = []  # Prepared quantum states
        self.shared_key = []  # Final shared key after sifting
        
    def generate_random_bits(self, num_bits: int) -> List[int]:
        """
        Generate random bits for transmission.
        
        Args:
            num_bits: Number of random bits to generate
            
        Returns:
            List of random bits (0 or 1)
        """
        self.bits = [random.randint(0, 1) for _ in range(num_bits)]
        return self.bits
    
    def choose_random_bases(self, num_bits: int) -> List[str]:
        """
        Choose random bases for each bit.
        
        Args:
            num_bits: Number of bases to choose
            
        Returns:
            List of bases ('+' or 'x')
        """
        self.bases = [random.choice(['+', 'x']) for _ in range(num_bits)]
        return self.bases
    
    def prepare_quantum_states(self) -> List[Tuple[complex, complex]]:
        """
        Prepare quantum states based on bits and bases.
        
        Returns:
            List of quantum states as (amplitude_0, amplitude_1) tuples
        """
        self.quantum_states = []
        
        for bit, base in zip(self.bits, self.bases):
            if base == '+':  # Rectilinear basis
                if bit == 0:
                    state = (1.0, 0.0)  # |0⟩
                else:
                    state = (0.0, 1.0)  # |1⟩
            else:  # Diagonal basis
                if bit == 0:
                    state = (1/np.sqrt(2), 1/np.sqrt(2))  # |+⟩
                else:
                    state = (1/np.sqrt(2), -1/np.sqrt(2))  # |-⟩
            
            self.quantum_states.append(state)
        
        return self.quantum_states
    
    def send_states(self, channel) -> bool:
        """
        Send quantum states through the channel.
        
        Args:
            channel: QuantumChannel instance
            
        Returns:
            True if successful
        """
        return channel.transmit(self.quantum_states)
    
    def sift_key(self, bob_bases: List[str]) -> List[int]:
        """
        Sift the key based on matching bases with Bob.
        
        Args:
            bob_bases: Bases chosen by Bob
            
        Returns:
            Sifted key bits
        """
        self.shared_key = []
        for i, (alice_base, bob_base) in enumerate(zip(self.bases, bob_bases)):
            if alice_base == bob_base:
                self.shared_key.append(self.bits[i])
        return self.shared_key
    
    def get_key_length(self) -> int:
        """Get the length of the shared key."""
        return len(self.shared_key)
    
    def get_key(self) -> List[int]:
        """Get the shared key."""
        return self.shared_key.copy()
    
    def reset(self):
        """Reset Alice's state for a new protocol run."""
        self.bits = []
        self.bases = []
        self.quantum_states = []
        self.shared_key = []
