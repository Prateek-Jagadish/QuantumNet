"""
Data Generator for ML Training

This module generates training data for the security classifier
based on quantum protocol simulations and security scenarios.
"""

import os
import sys
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
import random

# Import BB84 protocol
try:
    from ..quantum.bb84_protocol import BB84Protocol
except ImportError:
    # Fallback for when imported from outside the package
    sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'quantum'))
    from bb84_protocol import BB84Protocol


class DataGenerator:
    """
    DataGenerator class for creating training data for security classification.
    
    This class generates synthetic data based on quantum protocol simulations
    and various security scenarios for machine learning training.
    """
    
    def __init__(self, output_path: str = "data/training_data.csv"):
        """
        Initialize the data generator.
        
        Args:
            output_path: Path to save generated training data
        """
        self.output_path = output_path
        self.data = []
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    def generate_normal_data(self, num_samples: int = 1000) -> List[Dict]:
        """
        Generate normal operation data.
        
        Args:
            num_samples: Number of samples to generate
            
        Returns:
            List of normal operation data samples
        """
        normal_data = []
        
        for _ in range(num_samples):
            # Generate normal protocol parameters
            num_bits = random.randint(500, 2000)
            noise_level = random.uniform(0.0, 0.1)  # Low noise
            success_rate = random.uniform(0.95, 1.0)  # High success rate
            
            # Run BB84 protocol
            protocol = BB84Protocol(num_bits=num_bits, enable_eavesdropping=False)
            protocol.set_channel_parameters(noise_level=noise_level, success_rate=success_rate)
            
            result = protocol.run_protocol()
            
            if result['success']:
                # Generate additional features
                features = self._generate_additional_features(result, 'Normal')
                normal_data.append(features)
        
        return normal_data
    
    def generate_eavesdropping_data(self, num_samples: int = 1000) -> List[Dict]:
        """
        Generate eavesdropping attack data.
        
        Args:
            num_samples: Number of samples to generate
            
        Returns:
            List of eavesdropping data samples
        """
        eavesdropping_data = []
        
        for _ in range(num_samples):
            # Generate eavesdropping scenario parameters
            num_bits = random.randint(500, 2000)
            noise_level = random.uniform(0.0, 0.2)  # Higher noise
            success_rate = random.uniform(0.8, 1.0)  # Lower success rate
            
            # Run BB84 protocol with eavesdropping
            protocol = BB84Protocol(num_bits=num_bits, enable_eavesdropping=True)
            protocol.set_channel_parameters(noise_level=noise_level, success_rate=success_rate)
            
            result = protocol.run_protocol()
            
            if result['success']:
                # Generate additional features
                features = self._generate_additional_features(result, 'Eavesdropping')
                eavesdropping_data.append(features)
        
        return eavesdropping_data
    
    def generate_noise_data(self, num_samples: int = 1000) -> List[Dict]:
        """
        Generate high noise data.
        
        Args:
            num_samples: Number of samples to generate
            
        Returns:
            List of noise data samples
        """
        noise_data = []
        
        for _ in range(num_samples):
            # Generate high noise scenario parameters
            num_bits = random.randint(500, 2000)
            noise_level = random.uniform(0.2, 0.5)  # High noise
            success_rate = random.uniform(0.7, 0.95)  # Lower success rate
            
            # Run BB84 protocol
            protocol = BB84Protocol(num_bits=num_bits, enable_eavesdropping=False)
            protocol.set_channel_parameters(noise_level=noise_level, success_rate=success_rate)
            
            result = protocol.run_protocol()
            
            if result['success']:
                # Generate additional features
                features = self._generate_additional_features(result, 'Noise')
                noise_data.append(features)
        
        return noise_data
    
    def generate_attack_data(self, num_samples: int = 1000) -> List[Dict]:
        """
        Generate active attack data.
        
        Args:
            num_samples: Number of samples to generate
            
        Returns:
            List of attack data samples
        """
        attack_data = []
        
        for _ in range(num_samples):
            # Generate attack scenario parameters
            num_bits = random.randint(500, 2000)
            noise_level = random.uniform(0.3, 0.8)  # Very high noise
            success_rate = random.uniform(0.5, 0.9)  # Low success rate
            
            # Run BB84 protocol with eavesdropping (simulating attack)
            protocol = BB84Protocol(num_bits=num_bits, enable_eavesdropping=True)
            protocol.set_channel_parameters(noise_level=noise_level, success_rate=success_rate)
            
            result = protocol.run_protocol()
            
            if result['success']:
                # Generate additional features
                features = self._generate_additional_features(result, 'Attack')
                attack_data.append(features)
        
        return attack_data
    
    def _generate_additional_features(self, protocol_result: Dict, label: str) -> Dict:
        """
        Generate additional features for training data.
        
        Args:
            protocol_result: Result from BB84 protocol
            label: Data label
            
        Returns:
            Dictionary containing all features
        """
        # Base features from protocol
        features = {
            'key_length': protocol_result['key_length'],
            'detection_probability': protocol_result.get('detection_probability', 0.0),
            'protocol_success': 1 if protocol_result['protocol_success'] else 0,
            'label': label
        }
        
        # Calculate additional features
        if protocol_result['alice_key'] and protocol_result['bob_key']:
            # Hamming distance
            hamming_distance = sum(a != b for a, b in zip(protocol_result['alice_key'], protocol_result['bob_key']))
            features['hamming_distance'] = hamming_distance
            
            # Key entropy (simplified)
            key_entropy = self._calculate_entropy(protocol_result['alice_key'])
            features['key_entropy'] = key_entropy
        else:
            features['hamming_distance'] = 0
            features['key_entropy'] = 0
        
        # Simulate additional features
        features['transmission_success_rate'] = random.uniform(0.5, 1.0)
        features['noise_level'] = random.uniform(0.0, 0.8)
        features['eavesdropping_detected'] = 1 if label in ['Eavesdropping', 'Attack'] else 0
        features['error_rate'] = random.uniform(0.0, 0.3)
        features['timing_anomaly'] = random.uniform(0.0, 1.0) if label in ['Eavesdropping', 'Attack'] else random.uniform(0.0, 0.2)
        features['key_reuse_count'] = random.randint(0, 10)
        features['session_duration'] = random.uniform(1.0, 3600.0)  # seconds
        
        return features
    
    def _calculate_entropy(self, key: List[int]) -> float:
        """Calculate entropy of a key."""
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
    
    def generate_training_dataset(self, samples_per_class: int = 1000) -> pd.DataFrame:
        """
        Generate complete training dataset.
        
        Args:
            samples_per_class: Number of samples per class
            
        Returns:
            DataFrame containing training data
        """
        print("Generating training data...")
        
        # Generate data for each class
        normal_data = self.generate_normal_data(samples_per_class)
        eavesdropping_data = self.generate_eavesdropping_data(samples_per_class)
        noise_data = self.generate_noise_data(samples_per_class)
        attack_data = self.generate_attack_data(samples_per_class)
        
        # Combine all data
        all_data = normal_data + eavesdropping_data + noise_data + attack_data
        
        # Convert to DataFrame
        df = pd.DataFrame(all_data)
        
        # Shuffle data
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Save to file
        df.to_csv(self.output_path, index=False)
        
        print(f"Generated {len(df)} training samples")
        print(f"Data saved to {self.output_path}")
        
        return df
    
    def generate_validation_dataset(self, samples_per_class: int = 200) -> pd.DataFrame:
        """
        Generate validation dataset.
        
        Args:
            samples_per_class: Number of samples per class
            
        Returns:
            DataFrame containing validation data
        """
        print("Generating validation data...")
        
        # Generate validation data
        normal_data = self.generate_normal_data(samples_per_class)
        eavesdropping_data = self.generate_eavesdropping_data(samples_per_class)
        noise_data = self.generate_noise_data(samples_per_class)
        attack_data = self.generate_attack_data(samples_per_class)
        
        # Combine all data
        all_data = normal_data + eavesdropping_data + noise_data + attack_data
        
        # Convert to DataFrame
        df = pd.DataFrame(all_data)
        
        # Shuffle data
        df = df.sample(frac=1, random_state=123).reset_index(drop=True)
        
        # Save to file
        validation_path = self.output_path.replace('.csv', '_validation.csv')
        df.to_csv(validation_path, index=False)
        
        print(f"Generated {len(df)} validation samples")
        print(f"Data saved to {validation_path}")
        
        return df
    
    def load_training_data(self) -> pd.DataFrame:
        """
        Load training data from file.
        
        Returns:
            DataFrame containing training data
        """
        if not os.path.exists(self.output_path):
            raise FileNotFoundError(f"Training data not found at {self.output_path}")
        
        return pd.read_csv(self.output_path)
    
    def get_data_statistics(self) -> Dict:
        """
        Get statistics about the generated data.
        
        Returns:
            Dictionary containing data statistics
        """
        if not os.path.exists(self.output_path):
            return {'error': 'Data file not found'}
        
        df = pd.read_csv(self.output_path)
        
        stats = {
            'total_samples': len(df),
            'classes': df['label'].value_counts().to_dict(),
            'feature_columns': [col for col in df.columns if col != 'label'],
            'missing_values': df.isnull().sum().to_dict(),
            'data_types': df.dtypes.to_dict()
        }
        
        return stats
    
    def generate_real_time_data(self, num_samples: int = 100) -> List[Dict]:
        """
        Generate real-time data for testing.
        
        Args:
            num_samples: Number of samples to generate
            
        Returns:
            List of real-time data samples
        """
        real_time_data = []
        
        for _ in range(num_samples):
            # Randomly choose scenario
            scenario = random.choice(['Normal', 'Eavesdropping', 'Noise', 'Attack'])
            
            if scenario == 'Normal':
                data = self.generate_normal_data(1)
            elif scenario == 'Eavesdropping':
                data = self.generate_eavesdropping_data(1)
            elif scenario == 'Noise':
                data = self.generate_noise_data(1)
            else:  # Attack
                data = self.generate_attack_data(1)
            
            if data:
                real_time_data.append(data[0])
        
        return real_time_data
