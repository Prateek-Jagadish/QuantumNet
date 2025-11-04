"""
Bob - Quantum Key Distribution Receiver

Bob is the receiver in the BB84 protocol. He chooses random bases,
measures incoming quantum states, and extracts bits.
"""

import random
import numpy as np
from typing import List, Tuple, Optional


class Bob:
    """
    Bob class implementing the receiver side of BB84 protocol.
    
    Bob chooses random bases, measures incoming quantum states,
    and extracts bits based on his measurements.
    """
    
    def __init__(self, name: str = "Bob"):
        """
        Initialize Bob.
        
        Args:
            name: Name identifier for Bob
        """
        self.name = name
        self.bases = []  # Bases chosen for measurement
        self.measurements = []  # Measurement results
        self.extracted_bits = []  # Bits extracted from measurements
        self.shared_key = []  # Final shared key after sifting
        
    def choose_random_bases(self, num_bits: int) -> List[str]:
        """
        Choose random bases for measurement.
        
        Args:
            num_bits: Number of bases to choose
            
        Returns:
            List of bases ('+' or 'x')
        """
        self.bases = [random.choice(['+', 'x']) for _ in range(num_bits)]
        return self.bases
    
    def measure_quantum_states(self, quantum_states: List[Tuple[complex, complex]]) -> List[int]:
        """
        Measure quantum states and extract bits.
        
        Args:
            quantum_states: List of quantum states from Alice
            
        Returns:
            List of measured bits
        """
        self.measurements = []
        self.extracted_bits = []
        
        for i, state in enumerate(quantum_states):
            base = self.bases[i]
            amplitude_0, amplitude_1 = state
            
            # Calculate measurement probabilities
            if base == '+':  # Rectilinear basis
                prob_0 = abs(amplitude_0) ** 2
                prob_1 = abs(amplitude_1) ** 2
            else:  # Diagonal basis
                # Transform to diagonal basis
                amp_plus = (amplitude_0 + amplitude_1) / np.sqrt(2)
                amp_minus = (amplitude_0 - amplitude_1) / np.sqrt(2)
                prob_0 = abs(amp_plus) ** 2
                prob_1 = abs(amp_minus) ** 2
            
            # Normalize probabilities
            total_prob = prob_0 + prob_1
            if total_prob > 0:
                prob_0 /= total_prob
                prob_1 /= total_prob
            
            # Simulate measurement with quantum randomness
            measurement = random.choices([0, 1], weights=[prob_0, prob_1])[0]
            self.measurements.append(measurement)
            self.extracted_bits.append(measurement)
        
        return self.extracted_bits
    
    def sift_key(self, alice_bases: List[str]) -> List[int]:
        """
        Sift the key based on matching bases with Alice.
        
        Args:
            alice_bases: Bases chosen by Alice
            
        Returns:
            Sifted key bits
        """
        self.shared_key = []
        for i, (bob_base, alice_base) in enumerate(zip(self.bases, alice_bases)):
            if bob_base == alice_base:
                self.shared_key.append(self.extracted_bits[i])
        return self.shared_key
    
    def get_key_length(self) -> int:
        """Get the length of the shared key."""
        return len(self.shared_key)
    
    def get_key(self) -> List[int]:
        """Get the shared key."""
        return self.shared_key.copy()
    
    def get_bases(self) -> List[str]:
        """Get the bases used for measurement."""
        return self.bases.copy()
    
    def reset(self):
        """Reset Bob's state for a new protocol run."""
        self.bases = []
        self.measurements = []
        self.extracted_bits = []
        self.shared_key = []
