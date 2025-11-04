"""
Eve - Quantum Eavesdropper

Eve is the eavesdropper who attempts to intercept and measure
quantum states without being detected.
"""

import random
import numpy as np
from typing import List, Tuple, Optional


class Eve:
    """
    Eve class implementing an eavesdropper in BB84 protocol.
    
    Eve attempts to intercept quantum states, measure them,
    and resend them to Bob without being detected.
    """
    
    def __init__(self, name: str = "Eve"):
        """
        Initialize Eve.
        
        Args:
            name: Name identifier for Eve
        """
        self.name = name
        self.intercepted_states = []  # States intercepted from Alice
        self.eve_bases = []  # Bases chosen by Eve
        self.eve_measurements = []  # Eve's measurement results
        self.resent_states = []  # States resent to Bob
        self.detection_probability = 0.25  # Probability of detection per bit
        
    def intercept_states(self, quantum_states: List[Tuple[complex, complex]]) -> List[Tuple[complex, complex]]:
        """
        Intercept quantum states from Alice.
        
        Args:
            quantum_states: List of quantum states from Alice
            
        Returns:
            List of intercepted states
        """
        self.intercepted_states = quantum_states.copy()
        return self.intercepted_states
    
    def choose_eavesdropping_bases(self, num_bits: int) -> List[str]:
        """
        Choose random bases for eavesdropping measurements.
        
        Args:
            num_bits: Number of bases to choose
            
        Returns:
            List of bases ('+' or 'x')
        """
        self.eve_bases = [random.choice(['+', 'x']) for _ in range(num_bits)]
        return self.eve_bases
    
    def measure_intercepted_states(self) -> List[int]:
        """
        Measure intercepted quantum states.
        
        Returns:
            List of measured bits
        """
        self.eve_measurements = []
        
        for i, state in enumerate(self.intercepted_states):
            base = self.eve_bases[i]
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
            
            # Simulate measurement
            measurement = random.choices([0, 1], weights=[prob_0, prob_1])[0]
            self.eve_measurements.append(measurement)
        
        return self.eve_measurements
    
    def resend_states(self) -> List[Tuple[complex, complex]]:
        """
        Resend states to Bob based on Eve's measurements.
        
        Returns:
            List of resent quantum states
        """
        self.resent_states = []
        
        for measurement in self.eve_measurements:
            # Eve resends states based on her measurements
            # This introduces errors when bases don't match
            if measurement == 0:
                state = (1.0, 0.0)  # |0⟩
            else:
                state = (0.0, 1.0)  # |1⟩
            
            self.resent_states.append(state)
        
        return self.resent_states
    
    def calculate_detection_probability(self, alice_bases: List[str], bob_bases: List[str]) -> float:
        """
        Calculate the probability that Eve's presence is detected.
        
        Args:
            alice_bases: Bases chosen by Alice
            bob_bases: Bases chosen by Bob
            
        Returns:
            Detection probability
        """
        matching_bases = sum(1 for a, b in zip(alice_bases, bob_bases) if a == b)
        if matching_bases == 0:
            return 0.0
        
        # Eve introduces errors in 25% of cases when bases don't match
        eve_error_rate = 0.25
        detection_prob = 1 - (1 - eve_error_rate) ** matching_bases
        
        return detection_prob
    
    def get_intercepted_bits(self) -> List[int]:
        """Get the bits Eve intercepted."""
        return self.eve_measurements.copy()
    
    def get_eavesdropping_bases(self) -> List[str]:
        """Get the bases Eve used for eavesdropping."""
        return self.eve_bases.copy()
    
    def reset(self):
        """Reset Eve's state for a new protocol run."""
        self.intercepted_states = []
        self.eve_bases = []
        self.eve_measurements = []
        self.resent_states = []
