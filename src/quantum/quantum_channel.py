"""
QuantumChannel - Quantum Communication Channel

This class simulates a quantum channel for transmitting quantum states
between Alice and Bob, with optional eavesdropping by Eve.
"""

from typing import List, Tuple, Optional, Callable
import random


class QuantumChannel:
    """
    QuantumChannel class implementing a quantum communication channel.
    
    This channel can transmit quantum states between Alice and Bob,
    with optional eavesdropping capabilities for Eve.
    """
    
    def __init__(self, name: str = "QuantumChannel"):
        """
        Initialize the quantum channel.
        
        Args:
            name: Name identifier for the channel
        """
        self.name = name
        self.transmitted_states = []
        self.eavesdropper = None
        self.noise_level = 0.0  # Channel noise level (0.0 to 1.0)
        self.transmission_success_rate = 1.0  # Probability of successful transmission
        
    def set_eavesdropper(self, eve):
        """
        Set an eavesdropper for the channel.
        
        Args:
            eve: Eve instance to intercept transmissions
        """
        self.eavesdropper = eve
    
    def set_noise_level(self, noise_level: float):
        """
        Set the noise level of the channel.
        
        Args:
            noise_level: Noise level between 0.0 and 1.0
        """
        self.noise_level = max(0.0, min(1.0, noise_level))
    
    def set_transmission_success_rate(self, success_rate: float):
        """
        Set the transmission success rate.
        
        Args:
            success_rate: Success rate between 0.0 and 1.0
        """
        self.transmission_success_rate = max(0.0, min(1.0, success_rate))
    
    def transmit(self, quantum_states: List[Tuple[complex, complex]]) -> bool:
        """
        Transmit quantum states through the channel.
        
        Args:
            quantum_states: List of quantum states to transmit
            
        Returns:
            True if transmission was successful
        """
        # Check if transmission is successful
        if random.random() > self.transmission_success_rate:
            return False
        
        # Store transmitted states
        self.transmitted_states = quantum_states.copy()
        
        # Apply eavesdropping if Eve is present
        if self.eavesdropper:
            self._apply_eavesdropping()
        
        # Apply channel noise
        if self.noise_level > 0:
            self._apply_noise()
        
        return True
    
    def _apply_eavesdropping(self):
        """Apply eavesdropping by Eve."""
        if not self.eavesdropper:
            return
        
        # Eve intercepts the states
        intercepted = self.eavesdropper.intercept_states(self.transmitted_states)
        
        # Eve chooses bases and measures
        self.eavesdropper.choose_eavesdropping_bases(len(intercepted))
        self.eavesdropper.measure_intercepted_states()
        
        # Eve resends states to Bob
        self.transmitted_states = self.eavesdropper.resend_states()
    
    def _apply_noise(self):
        """Apply channel noise to transmitted states."""
        noisy_states = []
        
        for state in self.transmitted_states:
            amplitude_0, amplitude_1 = state
            
            # Add random noise to amplitudes
            noise_0 = random.gauss(0, self.noise_level * 0.1)
            noise_1 = random.gauss(0, self.noise_level * 0.1)
            
            noisy_amplitude_0 = amplitude_0 + noise_0
            noisy_amplitude_1 = amplitude_1 + noise_1
            
            # Normalize the state
            norm = (abs(noisy_amplitude_0) ** 2 + abs(noisy_amplitude_1) ** 2) ** 0.5
            if norm > 0:
                noisy_amplitude_0 /= norm
                noisy_amplitude_1 /= norm
            
            noisy_states.append((noisy_amplitude_0, noisy_amplitude_1))
        
        self.transmitted_states = noisy_states
    
    def get_transmitted_states(self) -> List[Tuple[complex, complex]]:
        """Get the transmitted quantum states."""
        return self.transmitted_states.copy()
    
    def clear_transmission(self):
        """Clear the current transmission."""
        self.transmitted_states = []
    
    def get_channel_info(self) -> dict:
        """Get information about the channel."""
        return {
            'name': self.name,
            'noise_level': self.noise_level,
            'transmission_success_rate': self.transmission_success_rate,
            'has_eavesdropper': self.eavesdropper is not None,
            'eavesdropper_name': self.eavesdropper.name if self.eavesdropper else None
        }
    
    def reset(self):
        """Reset the channel state."""
        self.transmitted_states = []
        self.eavesdropper = None
        self.noise_level = 0.0
        self.transmission_success_rate = 1.0
