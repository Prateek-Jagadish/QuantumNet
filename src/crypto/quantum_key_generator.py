"""
Quantum Key Generator

This module provides functionality to generate quantum keys using
the BB84 protocol and integrate them with the encryption system.
"""

import os
import sys
import time
from typing import Dict, List, Optional, Union
from datetime import datetime

# Import BB84 protocol
try:
    from ..quantum.bb84_protocol import BB84Protocol
except ImportError:
    # Fallback for when imported from outside the package
    sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'quantum'))
    from bb84_protocol import BB84Protocol
from .key_manager import KeyManager


class QuantumKeyGenerator:
    """
    QuantumKeyGenerator class for generating quantum keys using BB84 protocol.
    
    This class integrates the quantum key distribution protocol with
    the key management system for secure communication.
    """
    
    def __init__(self, key_manager: Optional[KeyManager] = None):
        """
        Initialize the quantum key generator.
        
        Args:
            key_manager: KeyManager instance (optional)
        """
        self.key_manager = key_manager or KeyManager()
        self.protocol_history = []  # Store protocol run history
        
    def generate_key_pair(self, user_id: str, session_id: str, 
                         num_bits: int = 1000, enable_eavesdropping: bool = False,
                         expiry_hours: int = 24) -> Dict:
        """
        Generate a quantum key pair for two users.
        
        Args:
            user_id: User identifier
            session_id: Session identifier
            num_bits: Number of bits for the quantum key
            enable_eavesdropping: Whether to simulate eavesdropping
            expiry_hours: Key expiry time in hours
            
        Returns:
            Dictionary containing key generation results
        """
        try:
            # Initialize BB84 protocol
            protocol = BB84Protocol(num_bits=num_bits, enable_eavesdropping=enable_eavesdropping)
            
            # Run the protocol
            protocol_result = protocol.run_protocol()
            
            if not protocol_result['success']:
                return {
                    'success': False,
                    'error': protocol_result.get('error', 'Protocol failed'),
                    'key_id': None
                }
            
            # Generate key IDs for both users
            alice_key_id = self.key_manager.generate_key_id(f"{user_id}_alice", session_id)
            bob_key_id = self.key_manager.generate_key_id(f"{user_id}_bob", session_id)
            
            # Store keys
            alice_key_stored = self.key_manager.store_key(
                alice_key_id, protocol_result['alice_key'], 
                f"{user_id}_alice", session_id, expiry_hours
            )
            
            bob_key_stored = self.key_manager.store_key(
                bob_key_id, protocol_result['bob_key'], 
                f"{user_id}_bob", session_id, expiry_hours
            )
            
            if not (alice_key_stored and bob_key_stored):
                return {
                    'success': False,
                    'error': 'Failed to store generated keys',
                    'key_id': None
                }
            
            # Record protocol run
            protocol_record = {
                'timestamp': datetime.now().isoformat(),
                'user_id': user_id,
                'session_id': session_id,
                'num_bits': num_bits,
                'enable_eavesdropping': enable_eavesdropping,
                'alice_key_id': alice_key_id,
                'bob_key_id': bob_key_id,
                'key_length': protocol_result['key_length'],
                'protocol_success': protocol_result['protocol_success'],
                'detection_probability': protocol_result.get('detection_probability', 0.0)
            }
            
            self.protocol_history.append(protocol_record)
            
            return {
                'success': True,
                'alice_key_id': alice_key_id,
                'bob_key_id': bob_key_id,
                'key_length': protocol_result['key_length'],
                'protocol_success': protocol_result['protocol_success'],
                'detection_probability': protocol_result.get('detection_probability', 0.0),
                'expiry_hours': expiry_hours,
                'protocol_record': protocol_record
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Key generation failed: {str(e)}',
                'key_id': None
            }
    
    def generate_single_key(self, user_id: str, session_id: str,
                          num_bits: int = 1000, enable_eavesdropping: bool = False,
                          expiry_hours: int = 24) -> Dict:
        """
        Generate a single quantum key for a user.
        
        Args:
            user_id: User identifier
            session_id: Session identifier
            num_bits: Number of bits for the quantum key
            enable_eavesdropping: Whether to simulate eavesdropping
            expiry_hours: Key expiry time in hours
            
        Returns:
            Dictionary containing key generation results
        """
        try:
            # Initialize BB84 protocol
            protocol = BB84Protocol(num_bits=num_bits, enable_eavesdropping=enable_eavesdropping)
            
            # Run the protocol
            protocol_result = protocol.run_protocol()
            
            if not protocol_result['success']:
                return {
                    'success': False,
                    'error': protocol_result.get('error', 'Protocol failed'),
                    'key_id': None
                }
            
            # Generate key ID
            key_id = self.key_manager.generate_key_id(user_id, session_id)
            
            # Store the key (use Alice's key as the single key)
            key_stored = self.key_manager.store_key(
                key_id, protocol_result['alice_key'], 
                user_id, session_id, expiry_hours
            )
            
            if not key_stored:
                return {
                    'success': False,
                    'error': 'Failed to store generated key',
                    'key_id': None
                }
            
            # Record protocol run
            protocol_record = {
                'timestamp': datetime.now().isoformat(),
                'user_id': user_id,
                'session_id': session_id,
                'num_bits': num_bits,
                'enable_eavesdropping': enable_eavesdropping,
                'key_id': key_id,
                'key_length': protocol_result['key_length'],
                'protocol_success': protocol_result['protocol_success'],
                'detection_probability': protocol_result.get('detection_probability', 0.0)
            }
            
            self.protocol_history.append(protocol_record)
            
            return {
                'success': True,
                'key_id': key_id,
                'key_length': protocol_result['key_length'],
                'protocol_success': protocol_result['protocol_success'],
                'detection_probability': protocol_result.get('detection_probability', 0.0),
                'expiry_hours': expiry_hours,
                'protocol_record': protocol_record
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Key generation failed: {str(e)}',
                'key_id': None
            }
    
    def get_key(self, key_id: str) -> Optional[str]:
        """
        Retrieve a quantum key by ID.
        
        Args:
            key_id: Key identifier
            
        Returns:
            Quantum key string or None
        """
        return self.key_manager.get_key(key_id)
    
    def is_key_valid(self, key_id: str) -> bool:
        """
        Check if a quantum key is valid.
        
        Args:
            key_id: Key identifier
            
        Returns:
            True if key is valid
        """
        return self.key_manager.is_key_valid(key_id)
    
    def extend_key_expiry(self, key_id: str, additional_hours: int) -> bool:
        """
        Extend the expiry time of a quantum key.
        
        Args:
            key_id: Key identifier
            additional_hours: Additional hours to extend
            
        Returns:
            True if successful
        """
        return self.key_manager.extend_key_expiry(key_id, additional_hours)
    
    def remove_key(self, key_id: str) -> bool:
        """
        Remove a quantum key.
        
        Args:
            key_id: Key identifier
            
        Returns:
            True if successful
        """
        return self.key_manager.remove_key(key_id)
    
    def get_user_keys(self, user_id: str) -> List[str]:
        """
        Get all quantum keys for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of key IDs
        """
        return self.key_manager.get_user_keys(user_id)
    
    def get_protocol_history(self, user_id: Optional[str] = None) -> List[Dict]:
        """
        Get protocol run history.
        
        Args:
            user_id: Filter by user ID (optional)
            
        Returns:
            List of protocol records
        """
        if user_id:
            return [record for record in self.protocol_history if record['user_id'] == user_id]
        return self.protocol_history.copy()
    
    def get_key_statistics(self) -> Dict:
        """
        Get statistics about quantum keys.
        
        Returns:
            Dictionary containing key statistics
        """
        stats = self.key_manager.get_key_statistics()
        stats['protocol_runs'] = len(self.protocol_history)
        stats['successful_protocols'] = sum(1 for record in self.protocol_history if record['protocol_success'])
        
        if self.protocol_history:
            avg_key_length = sum(record['key_length'] for record in self.protocol_history) / len(self.protocol_history)
            stats['average_key_length'] = avg_key_length
        
        return stats
    
    def cleanup_expired_keys(self) -> int:
        """
        Clean up expired quantum keys.
        
        Returns:
            Number of keys removed
        """
        return self.key_manager.cleanup_expired_keys()
    
    def simulate_eavesdropping_attack(self, user_id: str, session_id: str, 
                                    num_bits: int = 1000) -> Dict:
        """
        Simulate an eavesdropping attack on quantum key distribution.
        
        Args:
            user_id: User identifier
            session_id: Session identifier
            num_bits: Number of bits for the quantum key
            
        Returns:
            Dictionary containing attack simulation results
        """
        try:
            # Generate key with eavesdropping enabled
            result = self.generate_single_key(
                user_id, session_id, num_bits, 
                enable_eavesdropping=True, expiry_hours=1
            )
            
            if not result['success']:
                return result
            
            # Add attack analysis
            detection_probability = result['detection_probability']
            security_level = self._assess_security_level(detection_probability)
            
            result['attack_simulation'] = {
                'detection_probability': detection_probability,
                'security_level': security_level,
                'attack_detected': detection_probability > 0.1,
                'recommendation': self._get_security_recommendation(detection_probability)
            }
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Attack simulation failed: {str(e)}'
            }
    
    def _assess_security_level(self, detection_probability: float) -> str:
        """Assess security level based on detection probability."""
        if detection_probability < 0.05:
            return "HIGH"
        elif detection_probability < 0.15:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_security_recommendation(self, detection_probability: float) -> str:
        """Get security recommendation based on detection probability."""
        if detection_probability < 0.05:
            return "Key is secure for high-security applications"
        elif detection_probability < 0.15:
            return "Key is suitable for general use with monitoring"
        else:
            return "Key should be regenerated due to potential eavesdropping"
    
    def export_keys(self, output_file: str) -> bool:
        """
        Export all quantum keys to a file.
        
        Args:
            output_file: Output file path
            
        Returns:
            True if successful
        """
        return self.key_manager.export_keys(output_file)
    
    def import_keys(self, input_file: str) -> bool:
        """
        Import quantum keys from a file.
        
        Args:
            input_file: Input file path
            
        Returns:
            True if successful
        """
        return self.key_manager.import_keys(input_file)
