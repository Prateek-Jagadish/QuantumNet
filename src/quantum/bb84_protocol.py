"""
BB84Protocol - Quantum Key Distribution Protocol Implementation

This class implements the BB84 protocol for quantum key distribution,
coordinating between Alice, Bob, Eve, and the QuantumChannel.
"""

import random
import numpy as np
from typing import List, Tuple, Optional, Dict, Any

# Import quantum components
try:
    from .alice import Alice
    from .bob import Bob
    from .eve import Eve
    from .quantum_channel import QuantumChannel
except ImportError:
    # Fallback for when imported from outside the package
    import sys
    import os
    sys.path.append(os.path.dirname(__file__))
    from alice import Alice
    from bob import Bob
    from eve import Eve
    from quantum_channel import QuantumChannel


class BB84Protocol:
    """
    BB84Protocol class implementing the BB84 quantum key distribution protocol.
    
    This class coordinates the entire QKD process between Alice and Bob,
    with optional eavesdropping by Eve.
    """
    
    def __init__(self, num_bits: int = 1000, enable_eavesdropping: bool = False):
        """
        Initialize the BB84 protocol.
        
        Args:
            num_bits: Number of bits to generate for the key
            enable_eavesdropping: Whether to enable Eve's eavesdropping
        """
        self.num_bits = num_bits
        self.enable_eavesdropping = enable_eavesdropping
        
        # Initialize protocol participants
        self.alice = Alice()
        self.bob = Bob()
        self.eve = Eve() if enable_eavesdropping else None
        self.channel = QuantumChannel()
        
        # Protocol results
        self.alice_key = []
        self.bob_key = []
        self.eve_key = []
        self.key_length = 0
        self.detection_probability = 0.0
        self.protocol_success = False
        
    def run_protocol(self) -> Dict[str, Any]:
        """
        Run the complete BB84 protocol.
        
        Returns:
            Dictionary containing protocol results
        """
        try:
            # Step 1: Alice generates random bits and chooses bases
            alice_bits = self.alice.generate_random_bits(self.num_bits)
            alice_bases = self.alice.choose_random_bases(self.num_bits)
            
            # Step 2: Alice prepares quantum states
            quantum_states = self.alice.prepare_quantum_states()
            
            # Step 3: Set up eavesdropping if enabled
            if self.enable_eavesdropping and self.eve:
                self.channel.set_eavesdropper(self.eve)
            
            # Step 4: Bob chooses random bases
            bob_bases = self.bob.choose_random_bases(self.num_bits)
            
            # Step 5: Transmit quantum states through channel
            transmission_success = self.alice.send_states(self.channel)
            if not transmission_success:
                return self._create_failure_result("Transmission failed")
            
            # Step 6: Bob measures the received states
            transmitted_states = self.channel.get_transmitted_states()
            bob_measurements = self.bob.measure_quantum_states(transmitted_states)
            
            # Step 7: Sift keys based on matching bases
            self.alice_key = self.alice.sift_key(bob_bases)
            self.bob_key = self.bob.sift_key(alice_bases)
            
            # Step 8: Calculate detection probability if Eve was present
            if self.enable_eavesdropping and self.eve:
                self.detection_probability = self.eve.calculate_detection_probability(
                    alice_bases, bob_bases
                )
                self.eve_key = self.eve.get_intercepted_bits()
            
            # Step 9: Verify key agreement
            self.key_length = len(self.alice_key)
            self.protocol_success = self.alice_key == self.bob_key
            
            return self._create_success_result()
            
        except Exception as e:
            return self._create_failure_result(f"Protocol error: {str(e)}")
    
    def _create_success_result(self) -> Dict[str, Any]:
        """Create a successful protocol result."""
        result = {
            'success': True,
            'alice_key': self.alice_key.copy(),
            'bob_key': self.bob_key.copy(),
            'key_length': self.key_length,
            'protocol_success': self.protocol_success,
            'detection_probability': self.detection_probability,
            'enable_eavesdropping': self.enable_eavesdropping
        }
        
        if self.enable_eavesdropping and self.eve:
            result['eve_key'] = self.eve_key.copy()
            result['eve_bases'] = self.eve.get_eavesdropping_bases()
        
        return result
    
    def _create_failure_result(self, error_message: str) -> Dict[str, Any]:
        """Create a failed protocol result."""
        return {
            'success': False,
            'error': error_message,
            'alice_key': [],
            'bob_key': [],
            'key_length': 0,
            'protocol_success': False,
            'detection_probability': 0.0,
            'enable_eavesdropping': self.enable_eavesdropping
        }
    
    def get_key_statistics(self) -> Dict[str, Any]:
        """Get statistics about the generated keys."""
        if not self.protocol_success:
            return {'error': 'Protocol not successful'}
        
        # Calculate key statistics
        alice_key_binary = ''.join(map(str, self.alice_key))
        bob_key_binary = ''.join(map(str, self.bob_key))
        
        # Calculate Hamming distance
        hamming_distance = sum(a != b for a, b in zip(self.alice_key, self.bob_key))
        
        # Calculate key entropy (simplified)
        key_entropy = self._calculate_entropy(self.alice_key)
        
        stats = {
            'key_length': self.key_length,
            'hamming_distance': hamming_distance,
            'key_entropy': key_entropy,
            'alice_key_binary': alice_key_binary,
            'bob_key_binary': bob_key_binary,
            'keys_match': self.alice_key == self.bob_key
        }
        
        if self.enable_eavesdropping and self.eve:
            eve_key_binary = ''.join(map(str, self.eve_key))
            eve_hamming_distance = sum(a != b for a, b in zip(self.alice_key, self.eve_key))
            stats['eve_key_binary'] = eve_key_binary
            stats['eve_hamming_distance'] = eve_hamming_distance
            stats['detection_probability'] = self.detection_probability
        
        return stats
    
    def _calculate_entropy(self, key: List[int]) -> float:
        """Calculate the entropy of a key."""
        if not key:
            return 0.0
        
        # Count bit frequencies
        bit_counts = {0: 0, 1: 0}
        for bit in key:
            bit_counts[bit] += 1
        
        # Calculate entropy
        entropy = 0.0
        total_bits = len(key)
        for count in bit_counts.values():
            if count > 0:
                probability = count / total_bits
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def reset_protocol(self):
        """Reset the protocol for a new run."""
        self.alice.reset()
        self.bob.reset()
        if self.eve:
            self.eve.reset()
        self.channel.reset()
        
        self.alice_key = []
        self.bob_key = []
        self.eve_key = []
        self.key_length = 0
        self.detection_probability = 0.0
        self.protocol_success = False
    
    def set_channel_parameters(self, noise_level: float = 0.0, success_rate: float = 1.0):
        """
        Set channel parameters.
        
        Args:
            noise_level: Channel noise level (0.0 to 1.0)
            success_rate: Transmission success rate (0.0 to 1.0)
        """
        self.channel.set_noise_level(noise_level)
        self.channel.set_transmission_success_rate(success_rate)
    
    def get_protocol_info(self) -> Dict[str, Any]:
        """Get information about the protocol configuration."""
        return {
            'num_bits': self.num_bits,
            'enable_eavesdropping': self.enable_eavesdropping,
            'channel_info': self.channel.get_channel_info(),
            'participants': {
                'alice': self.alice.name,
                'bob': self.bob.name,
                'eve': self.eve.name if self.eve else None
            }
        }
