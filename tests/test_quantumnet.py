"""
QuantumNet Test Suite

Comprehensive pytest test suite for all QuantumNet components.
"""

import pytest
import os
import sys
import tempfile
import shutil
from unittest.mock import Mock, patch, MagicMock
import numpy as np
import pandas as pd

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Import modules to test
from src.quantum.alice import Alice
from src.quantum.bob import Bob
from src.quantum.eve import Eve
from src.quantum.quantum_channel import QuantumChannel
from src.quantum.bb84_protocol import BB84Protocol
from src.crypto.aes_encryption import AESEncryption
from src.crypto.key_manager import KeyManager
from src.crypto.quantum_key_generator import QuantumKeyGenerator
from src.ml.security_classifier import SecurityClassifier
from src.ml.data_generator import DataGenerator
from src.ml.model_manager import ModelManager
from src.server.database import DatabaseManager
from src.server.models import User, Message, SecurityEvent, Session


class TestAlice:
    """Test cases for Alice class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.alice = Alice("TestAlice")
    
    def test_init(self):
        """Test Alice initialization."""
        assert self.alice.name == "TestAlice"
        assert self.alice.bits == []
        assert self.alice.bases == []
        assert self.alice.quantum_states == []
        assert self.alice.shared_key == []
    
    def test_generate_random_bits(self):
        """Test random bit generation."""
        bits = self.alice.generate_random_bits(100)
        assert len(bits) == 100
        assert all(bit in [0, 1] for bit in bits)
    
    def test_choose_random_bases(self):
        """Test random base selection."""
        bases = self.alice.choose_random_bases(50)
        assert len(bases) == 50
        assert all(base in ['+', 'x'] for base in bases)
    
    def test_prepare_quantum_states(self):
        """Test quantum state preparation."""
        self.alice.bits = [0, 1, 0, 1]
        self.alice.bases = ['+', '+', 'x', 'x']
        
        states = self.alice.prepare_quantum_states()
        assert len(states) == 4
        assert all(len(state) == 2 for state in states)
    
    def test_sift_key(self):
        """Test key sifting."""
        self.alice.bits = [0, 1, 0, 1, 0]
        self.alice.bases = ['+', '+', 'x', '+', 'x']
        bob_bases = ['+', 'x', 'x', '+', '+']
        
        sifted_key = self.alice.sift_key(bob_bases)
        assert len(sifted_key) == 3  # Only matching bases
        assert sifted_key == [0, 0, 1]  # Bits where bases match
    
    def test_reset(self):
        """Test Alice reset."""
        self.alice.bits = [0, 1]
        self.alice.bases = ['+', 'x']
        self.alice.reset()
        
        assert self.alice.bits == []
        assert self.alice.bases == []
        assert self.alice.quantum_states == []
        assert self.alice.shared_key == []


class TestBob:
    """Test cases for Bob class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.bob = Bob("TestBob")
    
    def test_init(self):
        """Test Bob initialization."""
        assert self.bob.name == "TestBob"
        assert self.bob.bases == []
        assert self.bob.measurements == []
        assert self.bob.extracted_bits == []
        assert self.bob.shared_key == []
    
    def test_choose_random_bases(self):
        """Test random base selection."""
        bases = self.bob.choose_random_bases(50)
        assert len(bases) == 50
        assert all(base in ['+', 'x'] for base in bases)
    
    def test_measure_quantum_states(self):
        """Test quantum state measurement."""
        quantum_states = [(1.0, 0.0), (0.0, 1.0), (1/np.sqrt(2), 1/np.sqrt(2))]
        self.bob.bases = ['+', '+', 'x']
        
        measurements = self.bob.measure_quantum_states(quantum_states)
        assert len(measurements) == 3
        assert all(measurement in [0, 1] for measurement in measurements)
    
    def test_sift_key(self):
        """Test key sifting."""
        self.bob.bases = ['+', 'x', '+', 'x', '+']
        self.bob.extracted_bits = [0, 1, 0, 1, 0]
        alice_bases = ['+', '+', 'x', '+', 'x']
        
        sifted_key = self.bob.sift_key(alice_bases)
        assert len(sifted_key) == 3  # Only matching bases
        assert sifted_key == [0, 0, 0]  # Bits where bases match
    
    def test_reset(self):
        """Test Bob reset."""
        self.bob.bases = ['+', 'x']
        self.bob.measurements = [0, 1]
        self.bob.reset()
        
        assert self.bob.bases == []
        assert self.bob.measurements == []
        assert self.bob.extracted_bits == []
        assert self.bob.shared_key == []


class TestEve:
    """Test cases for Eve class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.eve = Eve("TestEve")
    
    def test_init(self):
        """Test Eve initialization."""
        assert self.eve.name == "TestEve"
        assert self.eve.intercepted_states == []
        assert self.eve.eve_bases == []
        assert self.eve.eve_measurements == []
        assert self.eve.resent_states == []
        assert self.eve.detection_probability == 0.25
    
    def test_intercept_states(self):
        """Test state interception."""
        states = [(1.0, 0.0), (0.0, 1.0)]
        intercepted = self.eve.intercept_states(states)
        assert intercepted == states
        assert self.eve.intercepted_states == states
    
    def test_choose_eavesdropping_bases(self):
        """Test eavesdropping base selection."""
        bases = self.eve.choose_eavesdropping_bases(50)
        assert len(bases) == 50
        assert all(base in ['+', 'x'] for base in bases)
    
    def test_measure_intercepted_states(self):
        """Test intercepted state measurement."""
        self.eve.intercepted_states = [(1.0, 0.0), (0.0, 1.0)]
        self.eve.eve_bases = ['+', '+']
        
        measurements = self.eve.measure_intercepted_states()
        assert len(measurements) == 2
        assert all(measurement in [0, 1] for measurement in measurements)
    
    def test_resend_states(self):
        """Test state resending."""
        self.eve.eve_measurements = [0, 1]
        resent = self.eve.resend_states()
        assert len(resent) == 2
        assert all(len(state) == 2 for state in resent)
    
    def test_calculate_detection_probability(self):
        """Test detection probability calculation."""
        alice_bases = ['+', '+', 'x', '+']
        bob_bases = ['+', 'x', 'x', '+']
        
        prob = self.eve.calculate_detection_probability(alice_bases, bob_bases)
        assert 0 <= prob <= 1
    
    def test_reset(self):
        """Test Eve reset."""
        self.eve.intercepted_states = [(1.0, 0.0)]
        self.eve.eve_bases = ['+']
        self.eve.reset()
        
        assert self.eve.intercepted_states == []
        assert self.eve.eve_bases == []
        assert self.eve.eve_measurements == []
        assert self.eve.resent_states == []


class TestQuantumChannel:
    """Test cases for QuantumChannel class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.channel = QuantumChannel("TestChannel")
    
    def test_init(self):
        """Test QuantumChannel initialization."""
        assert self.channel.name == "TestChannel"
        assert self.channel.transmitted_states == []
        assert self.channel.eavesdropper is None
        assert self.channel.noise_level == 0.0
        assert self.channel.transmission_success_rate == 1.0
    
    def test_set_eavesdropper(self):
        """Test eavesdropper setting."""
        eve = Eve()
        self.channel.set_eavesdropper(eve)
        assert self.channel.eavesdropper == eve
    
    def test_set_noise_level(self):
        """Test noise level setting."""
        self.channel.set_noise_level(0.5)
        assert self.channel.noise_level == 0.5
        
        # Test bounds
        self.channel.set_noise_level(-0.1)
        assert self.channel.noise_level == 0.0
        
        self.channel.set_noise_level(1.5)
        assert self.channel.noise_level == 1.0
    
    def test_set_transmission_success_rate(self):
        """Test transmission success rate setting."""
        self.channel.set_transmission_success_rate(0.8)
        assert self.channel.transmission_success_rate == 0.8
        
        # Test bounds
        self.channel.set_transmission_success_rate(-0.1)
        assert self.channel.transmission_success_rate == 0.0
        
        self.channel.set_transmission_success_rate(1.5)
        assert self.channel.transmission_success_rate == 1.0
    
    def test_transmit(self):
        """Test quantum state transmission."""
        states = [(1.0, 0.0), (0.0, 1.0)]
        success = self.channel.transmit(states)
        assert success is True
        assert len(self.channel.transmitted_states) == 2
    
    def test_get_channel_info(self):
        """Test channel information retrieval."""
        info = self.channel.get_channel_info()
        assert 'name' in info
        assert 'noise_level' in info
        assert 'transmission_success_rate' in info
        assert 'has_eavesdropper' in info
    
    def test_reset(self):
        """Test channel reset."""
        self.channel.transmitted_states = [(1.0, 0.0)]
        self.channel.noise_level = 0.5
        self.channel.reset()
        
        assert self.channel.transmitted_states == []
        assert self.channel.eavesdropper is None
        assert self.channel.noise_level == 0.0
        assert self.channel.transmission_success_rate == 1.0


class TestBB84Protocol:
    """Test cases for BB84Protocol class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.protocol = BB84Protocol(num_bits=100, enable_eavesdropping=False)
    
    def test_init(self):
        """Test BB84Protocol initialization."""
        assert self.protocol.num_bits == 100
        assert self.protocol.enable_eavesdropping is False
        assert self.protocol.alice is not None
        assert self.protocol.bob is not None
        assert self.protocol.eve is None
        assert self.protocol.channel is not None
    
    def test_run_protocol_no_eavesdropping(self):
        """Test protocol run without eavesdropping."""
        result = self.protocol.run_protocol()
        assert result['success'] is True
        assert 'alice_key' in result
        assert 'bob_key' in result
        assert 'key_length' in result
        assert 'protocol_success' in result
    
    def test_run_protocol_with_eavesdropping(self):
        """Test protocol run with eavesdropping."""
        protocol = BB84Protocol(num_bits=100, enable_eavesdropping=True)
        result = protocol.run_protocol()
        assert result['success'] is True
        assert 'detection_probability' in result
        assert 'eve_key' in result
    
    def test_get_key_statistics(self):
        """Test key statistics retrieval."""
        self.protocol.run_protocol()
        stats = self.protocol.get_key_statistics()
        assert 'key_length' in stats
        assert 'hamming_distance' in stats
        assert 'key_entropy' in stats
    
    def test_set_channel_parameters(self):
        """Test channel parameter setting."""
        self.protocol.set_channel_parameters(noise_level=0.1, success_rate=0.9)
        assert self.protocol.channel.noise_level == 0.1
        assert self.protocol.channel.transmission_success_rate == 0.9
    
    def test_reset_protocol(self):
        """Test protocol reset."""
        self.protocol.run_protocol()
        self.protocol.reset_protocol()
        
        assert self.protocol.alice_key == []
        assert self.protocol.bob_key == []
        assert self.protocol.key_length == 0
        assert self.protocol.protocol_success is False


class TestAESEncryption:
    """Test cases for AESEncryption class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.aes = AESEncryption()
    
    def test_init(self):
        """Test AESEncryption initialization."""
        assert self.aes.key_size == 32
        assert self.aes.block_size == 16
    
    def test_generate_iv(self):
        """Test IV generation."""
        iv = self.aes.generate_iv()
        assert len(iv) == 16
        assert isinstance(iv, bytes)
    
    def test_derive_key_string(self):
        """Test key derivation from string."""
        quantum_key = "test_key_string"
        derived_key = self.aes.derive_key(quantum_key)
        assert len(derived_key) == 32
        assert isinstance(derived_key, bytes)
    
    def test_derive_key_list(self):
        """Test key derivation from list."""
        quantum_key = [0, 1, 0, 1, 0]
        derived_key = self.aes.derive_key(quantum_key)
        assert len(derived_key) == 32
        assert isinstance(derived_key, bytes)
    
    def test_derive_key_bytes(self):
        """Test key derivation from bytes."""
        quantum_key = b"test_key_bytes"
        derived_key = self.aes.derive_key(quantum_key)
        assert len(derived_key) == 32
        assert isinstance(derived_key, bytes)
    
    def test_encrypt_decrypt_string(self):
        """Test string encryption and decryption."""
        plaintext = "Hello, Quantum World!"
        quantum_key = "test_quantum_key"
        
        # Encrypt
        encrypt_result = self.aes.encrypt(plaintext, quantum_key)
        assert encrypt_result['success'] is True
        assert 'encrypted_data' in encrypt_result
        assert 'iv' in encrypt_result
        
        # Decrypt
        decrypt_result = self.aes.decrypt(
            encrypt_result['encrypted_data'],
            encrypt_result['iv'],
            quantum_key
        )
        assert decrypt_result['success'] is True
        assert decrypt_result['decrypted_data'] == plaintext
    
    def test_encrypt_decrypt_bytes(self):
        """Test bytes encryption and decryption."""
        plaintext = b"Hello, Quantum World!"
        quantum_key = "test_quantum_key"
        
        # Encrypt
        encrypt_result = self.aes.encrypt(plaintext, quantum_key)
        assert encrypt_result['success'] is True
        
        # Decrypt
        decrypt_result = self.aes.decrypt(
            encrypt_result['encrypted_data'],
            encrypt_result['iv'],
            quantum_key
        )
        assert decrypt_result['success'] is True
        assert decrypt_result['decrypted_data'] == plaintext
    
    def test_get_key_info(self):
        """Test key information retrieval."""
        quantum_key = "test_key"
        info = self.aes.get_key_info(quantum_key)
        assert 'original_type' in info
        assert 'derived_key_length' in info
        assert 'key_size_bits' in info
        assert info['key_size_bits'] == 256


class TestKeyManager:
    """Test cases for KeyManager class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.key_manager = KeyManager(storage_path=self.temp_dir)
    
    def teardown_method(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)
    
    def test_init(self):
        """Test KeyManager initialization."""
        assert self.key_manager.storage_path == self.temp_dir
        assert self.key_manager.default_expiry_hours == 24
        assert isinstance(self.key_manager.keys, dict)
        assert isinstance(self.key_manager.key_metadata, dict)
    
    def test_generate_key_id(self):
        """Test key ID generation."""
        key_id = self.key_manager.generate_key_id("user1", "session1")
        assert len(key_id) == 16
        assert isinstance(key_id, str)
    
    def test_store_key(self):
        """Test key storage."""
        key_id = self.key_manager.generate_key_id("user1", "session1")
        quantum_key = [0, 1, 0, 1, 0]
        
        success = self.key_manager.store_key(key_id, quantum_key, "user1", "session1")
        assert success is True
        assert key_id in self.key_manager.keys
        assert key_id in self.key_manager.key_metadata
    
    def test_get_key(self):
        """Test key retrieval."""
        key_id = self.key_manager.generate_key_id("user1", "session1")
        quantum_key = [0, 1, 0, 1, 0]
        
        self.key_manager.store_key(key_id, quantum_key, "user1", "session1")
        retrieved_key = self.key_manager.get_key(key_id)
        assert retrieved_key == "01010"
    
    def test_is_key_valid(self):
        """Test key validity check."""
        key_id = self.key_manager.generate_key_id("user1", "session1")
        quantum_key = [0, 1, 0, 1, 0]
        
        self.key_manager.store_key(key_id, quantum_key, "user1", "session1")
        assert self.key_manager.is_key_valid(key_id) is True
        
        # Test invalid key
        assert self.key_manager.is_key_valid("invalid_key") is False
    
    def test_extend_key_expiry(self):
        """Test key expiry extension."""
        key_id = self.key_manager.generate_key_id("user1", "session1")
        quantum_key = [0, 1, 0, 1, 0]
        
        self.key_manager.store_key(key_id, quantum_key, "user1", "session1")
        success = self.key_manager.extend_key_expiry(key_id, 12)
        assert success is True
    
    def test_remove_key(self):
        """Test key removal."""
        key_id = self.key_manager.generate_key_id("user1", "session1")
        quantum_key = [0, 1, 0, 1, 0]
        
        self.key_manager.store_key(key_id, quantum_key, "user1", "session1")
        success = self.key_manager.remove_key(key_id)
        assert success is True
        assert key_id not in self.key_manager.keys
    
    def test_get_user_keys(self):
        """Test user key retrieval."""
        key_id1 = self.key_manager.generate_key_id("user1", "session1")
        key_id2 = self.key_manager.generate_key_id("user1", "session2")
        quantum_key = [0, 1, 0, 1, 0]
        
        self.key_manager.store_key(key_id1, quantum_key, "user1", "session1")
        self.key_manager.store_key(key_id2, quantum_key, "user1", "session2")
        
        user_keys = self.key_manager.get_user_keys("user1")
        assert len(user_keys) == 2
        assert key_id1 in user_keys
        assert key_id2 in user_keys
    
    def test_get_key_statistics(self):
        """Test key statistics retrieval."""
        key_id = self.key_manager.generate_key_id("user1", "session1")
        quantum_key = [0, 1, 0, 1, 0]
        
        self.key_manager.store_key(key_id, quantum_key, "user1", "session1")
        stats = self.key_manager.get_key_statistics()
        
        assert 'total_keys' in stats
        assert 'valid_keys' in stats
        assert 'expired_keys' in stats
        assert stats['total_keys'] == 1


class TestSecurityClassifier:
    """Test cases for SecurityClassifier class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.classifier = SecurityClassifier(model_path=os.path.join(self.temp_dir, "test_model.pkl"))
    
    def teardown_method(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)
    
    def test_init(self):
        """Test SecurityClassifier initialization."""
        assert self.classifier.model_path.endswith("test_model.pkl")
        assert self.classifier.is_trained is False
        assert len(self.classifier.class_names) == 4
        assert self.classifier.class_names == ['Normal', 'Eavesdropping', 'Noise', 'Attack']
    
    def test_prepare_features(self):
        """Test feature preparation."""
        data = pd.DataFrame({
            'key_length': [100, 200],
            'detection_probability': [0.1, 0.2],
            'hamming_distance': [5, 10],
            'key_entropy': [0.8, 0.9],
            'transmission_success_rate': [0.95, 0.98],
            'noise_level': [0.05, 0.1],
            'protocol_success': [1, 1],
            'eavesdropping_detected': [0, 0],
            'error_rate': [0.02, 0.01],
            'timing_anomaly': [0.1, 0.2],
            'key_reuse_count': [0, 1],
            'session_duration': [100, 200],
            'label': ['Normal', 'Normal']
        })
        
        features = self.classifier.prepare_features(data)
        assert features.shape[0] == 2
        assert features.shape[1] == 12
        assert len(self.classifier.feature_names) == 12
    
    def test_train(self):
        """Test model training."""
        # Create sample training data
        X = np.random.rand(100, 12)
        y = np.random.randint(0, 4, 100)
        
        result = self.classifier.train(X, y)
        assert result['success'] is True
        assert 'train_score' in result
        assert 'test_score' in result
        assert 'cv_mean' in result
        assert self.classifier.is_trained is True
    
    def test_predict(self):
        """Test model prediction."""
        # Train model first
        X_train = np.random.rand(100, 12)
        y_train = np.random.randint(0, 4, 100)
        self.classifier.train(X_train, y_train)
        
        # Test prediction
        X_test = np.random.rand(10, 12)
        predictions = self.classifier.predict(X_test)
        assert len(predictions) == 10
        assert all(pred in [0, 1, 2, 3] for pred in predictions)
    
    def test_predict_proba(self):
        """Test prediction probabilities."""
        # Train model first
        X_train = np.random.rand(100, 12)
        y_train = np.random.randint(0, 4, 100)
        self.classifier.train(X_train, y_train)
        
        # Test probability prediction
        X_test = np.random.rand(5, 12)
        probabilities = self.classifier.predict_proba(X_test)
        assert probabilities.shape == (5, 4)
        assert np.allclose(probabilities.sum(axis=1), 1.0)
    
    def test_predict_security_threat(self):
        """Test security threat prediction."""
        # Train model first
        X_train = np.random.rand(100, 12)
        y_train = np.random.randint(0, 4, 100)
        self.classifier.train(X_train, y_train)
        
        # Test threat prediction
        features = {
            'key_length': 1000,
            'detection_probability': 0.1,
            'hamming_distance': 5,
            'key_entropy': 0.8,
            'transmission_success_rate': 0.95,
            'noise_level': 0.05,
            'protocol_success': 1,
            'eavesdropping_detected': 0,
            'error_rate': 0.02,
            'timing_anomaly': 0.1,
            'key_reuse_count': 0,
            'session_duration': 100
        }
        
        result = self.classifier.predict_security_threat(features)
        assert result['success'] is True
        assert 'prediction' in result
        assert 'prediction_label' in result
        assert 'threat_level' in result
        assert 'confidence' in result
    
    def test_get_feature_importance(self):
        """Test feature importance retrieval."""
        # Train model first
        X_train = np.random.rand(100, 12)
        y_train = np.random.randint(0, 4, 100)
        self.classifier.train(X_train, y_train)
        
        importance = self.classifier.get_feature_importance()
        assert len(importance) == 12
        assert all(imp >= 0 for imp in importance.values())
    
    def test_save_load_model(self):
        """Test model saving and loading."""
        # Train model first
        X_train = np.random.rand(100, 12)
        y_train = np.random.randint(0, 4, 100)
        self.classifier.train(X_train, y_train)
        
        # Save model
        save_success = self.classifier.save_model()
        assert save_success is True
        
        # Create new classifier and load model
        new_classifier = SecurityClassifier(model_path=self.classifier.model_path)
        load_success = new_classifier.load_model()
        assert load_success is True
        assert new_classifier.is_trained is True


class TestDataGenerator:
    """Test cases for DataGenerator class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.data_generator = DataGenerator(output_path=os.path.join(self.temp_dir, "test_data.csv"))
    
    def teardown_method(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)
    
    def test_init(self):
        """Test DataGenerator initialization."""
        assert self.data_generator.output_path.endswith("test_data.csv")
        assert isinstance(self.data_generator.data, list)
    
    def test_generate_normal_data(self):
        """Test normal data generation."""
        data = self.data_generator.generate_normal_data(10)
        assert len(data) <= 10  # May be less due to protocol failures
        assert all('label' in item for item in data)
        assert all(item['label'] == 'Normal' for item in data)
    
    def test_generate_eavesdropping_data(self):
        """Test eavesdropping data generation."""
        data = self.data_generator.generate_eavesdropping_data(10)
        assert len(data) <= 10
        assert all('label' in item for item in data)
        assert all(item['label'] == 'Eavesdropping' for item in data)
    
    def test_generate_noise_data(self):
        """Test noise data generation."""
        data = self.data_generator.generate_noise_data(10)
        assert len(data) <= 10
        assert all('label' in item for item in data)
        assert all(item['label'] == 'Noise' for item in data)
    
    def test_generate_attack_data(self):
        """Test attack data generation."""
        data = self.data_generator.generate_attack_data(10)
        assert len(data) <= 10
        assert all('label' in item for item in data)
        assert all(item['label'] == 'Attack' for item in data)
    
    def test_generate_training_dataset(self):
        """Test complete training dataset generation."""
        df = self.data_generator.generate_training_dataset(samples_per_class=5)
        assert isinstance(df, pd.DataFrame)
        assert len(df) > 0
        assert 'label' in df.columns
    
    def test_generate_validation_dataset(self):
        """Test validation dataset generation."""
        df = self.data_generator.generate_validation_dataset(samples_per_class=3)
        assert isinstance(df, pd.DataFrame)
        assert len(df) > 0
        assert 'label' in df.columns
    
    def test_generate_real_time_data(self):
        """Test real-time data generation."""
        data = self.data_generator.generate_real_time_data(5)
        assert len(data) == 5
        assert all('label' in item for item in data)
        assert all(item['label'] in ['Normal', 'Eavesdropping', 'Noise', 'Attack'] for item in data)


class TestModelManager:
    """Test cases for ModelManager class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.model_manager = ModelManager(
            models_dir=os.path.join(self.temp_dir, "models"),
            data_dir=os.path.join(self.temp_dir, "data")
        )
    
    def teardown_method(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)
    
    def test_init(self):
        """Test ModelManager initialization."""
        assert os.path.exists(self.model_manager.models_dir)
        assert os.path.exists(self.model_manager.data_dir)
        assert self.model_manager.classifier is not None
        assert self.model_manager.data_generator is not None
    
    def test_prepare_training_data(self):
        """Test training data preparation."""
        X, y = self.model_manager.prepare_training_data(samples_per_class=5)
        assert isinstance(X, np.ndarray)
        assert isinstance(y, np.ndarray)
        assert len(X) == len(y)
    
    def test_train_model(self):
        """Test model training."""
        result = self.model_manager.train_model(samples_per_class=10)
        assert result['success'] is True
        assert 'train_score' in result
        assert 'test_score' in result
    
    def test_evaluate_model(self):
        """Test model evaluation."""
        # Train model first
        self.model_manager.train_model(samples_per_class=10)
        
        result = self.model_manager.evaluate_model(samples_per_class=5)
        assert result['success'] is True
        assert 'accuracy' in result
    
    def test_predict_security_threat(self):
        """Test security threat prediction."""
        # Train model first
        self.model_manager.train_model(samples_per_class=10)
        
        features = {
            'key_length': 1000,
            'detection_probability': 0.1,
            'hamming_distance': 5,
            'key_entropy': 0.8,
            'transmission_success_rate': 0.95,
            'noise_level': 0.05,
            'protocol_success': 1,
            'eavesdropping_detected': 0,
            'error_rate': 0.02,
            'timing_anomaly': 0.1,
            'key_reuse_count': 0,
            'session_duration': 100
        }
        
        result = self.model_manager.predict_security_threat(features)
        assert result['success'] is True
        assert 'prediction' in result
    
    def test_batch_predict(self):
        """Test batch prediction."""
        # Train model first
        self.model_manager.train_model(samples_per_class=10)
        
        data = [
            {
                'key_length': 1000,
                'detection_probability': 0.1,
                'hamming_distance': 5,
                'key_entropy': 0.8,
                'transmission_success_rate': 0.95,
                'noise_level': 0.05,
                'protocol_success': 1,
                'eavesdropping_detected': 0,
                'error_rate': 0.02,
                'timing_anomaly': 0.1,
                'key_reuse_count': 0,
                'session_duration': 100
            }
        ]
        
        results = self.model_manager.batch_predict(data)
        assert len(results) == 1
        assert results[0]['success'] is True
    
    def test_get_model_performance(self):
        """Test model performance retrieval."""
        # Train model first
        self.model_manager.train_model(samples_per_class=10)
        
        performance = self.model_manager.get_model_performance()
        assert 'is_trained' in performance
        assert 'feature_names' in performance
        assert 'class_names' in performance
        assert performance['is_trained'] is True


class TestDatabaseManager:
    """Test cases for DatabaseManager class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_manager = DatabaseManager(db_path=os.path.join(self.temp_dir, "test.db"))
    
    def teardown_method(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)
    
    def test_init(self):
        """Test DatabaseManager initialization."""
        assert os.path.exists(self.db_manager.db_path)
        assert isinstance(self.db_manager.db_path, str)
    
    def test_create_user(self):
        """Test user creation."""
        user_id = self.db_manager.create_user("testuser", "test@example.com", "password123")
        assert user_id is not None
        assert isinstance(user_id, int)
    
    def test_authenticate_user(self):
        """Test user authentication."""
        # Create user first
        user_id = self.db_manager.create_user("testuser", "test@example.com", "password123")
        
        # Test authentication
        user = self.db_manager.authenticate_user("testuser", "password123")
        assert user is not None
        assert user['username'] == "testuser"
        assert user['email'] == "test@example.com"
    
    def test_get_user_by_id(self):
        """Test user retrieval by ID."""
        # Create user first
        user_id = self.db_manager.create_user("testuser", "test@example.com", "password123")
        
        # Test retrieval
        user = self.db_manager.get_user_by_id(user_id)
        assert user is not None
        assert user['id'] == user_id
        assert user['username'] == "testuser"
    
    def test_create_message(self):
        """Test message creation."""
        # Create user first
        user_id = self.db_manager.create_user("testuser", "test@example.com", "password123")
        
        # Create message
        message_id = self.db_manager.create_message(user_id, "Hello World!")
        assert message_id is not None
        assert isinstance(message_id, int)
    
    def test_get_recent_messages(self):
        """Test recent message retrieval."""
        # Create user and message
        user_id = self.db_manager.create_user("testuser", "test@example.com", "password123")
        self.db_manager.create_message(user_id, "Hello World!")
        
        # Test retrieval
        messages = self.db_manager.get_recent_messages(limit=10)
        assert len(messages) == 1
        assert messages[0]['content'] == "Hello World!"
    
    def test_create_security_event(self):
        """Test security event creation."""
        # Create user first
        user_id = self.db_manager.create_user("testuser", "test@example.com", "password123")
        
        # Create security event
        event_id = self.db_manager.create_security_event(
            user_id, "TEST_EVENT", "Test security event", "LOW"
        )
        assert event_id is not None
        assert isinstance(event_id, int)
    
    def test_get_user_security_events(self):
        """Test user security event retrieval."""
        # Create user and event
        user_id = self.db_manager.create_user("testuser", "test@example.com", "password123")
        self.db_manager.create_security_event(user_id, "TEST_EVENT", "Test event", "LOW")
        
        # Test retrieval
        events = self.db_manager.get_user_security_events(user_id, limit=10)
        assert len(events) == 1
        assert events[0]['event_type'] == "TEST_EVENT"
    
    def test_get_database_stats(self):
        """Test database statistics retrieval."""
        # Create some test data
        user_id = self.db_manager.create_user("testuser", "test@example.com", "password123")
        self.db_manager.create_message(user_id, "Test message")
        self.db_manager.create_security_event(user_id, "TEST_EVENT", "Test event", "LOW")
        
        # Test statistics
        stats = self.db_manager.get_database_stats()
        assert 'active_users' in stats
        assert 'total_messages' in stats
        assert 'total_security_events' in stats
        assert stats['active_users'] == 1
        assert stats['total_messages'] == 1
        assert stats['total_security_events'] == 1


class TestModels:
    """Test cases for model classes."""
    
    def test_user_model(self):
        """Test User model."""
        user = User(id=1, username="testuser", email="test@example.com")
        assert user.id == 1
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        
        # Test to_dict
        user_dict = user.to_dict()
        assert user_dict['id'] == 1
        assert user_dict['username'] == "testuser"
        
        # Test from_dict
        new_user = User.from_dict(user_dict)
        assert new_user.id == 1
        assert new_user.username == "testuser"
    
    def test_message_model(self):
        """Test Message model."""
        message = Message(id=1, user_id=1, content="Hello World!")
        assert message.id == 1
        assert message.user_id == 1
        assert message.content == "Hello World!"
        
        # Test to_dict
        message_dict = message.to_dict()
        assert message_dict['id'] == 1
        assert message_dict['content'] == "Hello World!"
        
        # Test from_dict
        new_message = Message.from_dict(message_dict)
        assert new_message.id == 1
        assert new_message.content == "Hello World!"
    
    def test_security_event_model(self):
        """Test SecurityEvent model."""
        event = SecurityEvent(id=1, user_id=1, event_type="TEST", description="Test event")
        assert event.id == 1
        assert event.user_id == 1
        assert event.event_type == "TEST"
        assert event.description == "Test event"
        
        # Test to_dict
        event_dict = event.to_dict()
        assert event_dict['id'] == 1
        assert event_dict['event_type'] == "TEST"
        
        # Test from_dict
        new_event = SecurityEvent.from_dict(event_dict)
        assert new_event.id == 1
        assert new_event.event_type == "TEST"
    
    def test_session_model(self):
        """Test Session model."""
        session = Session(id=1, user_id=1, session_id="test_session")
        assert session.id == 1
        assert session.user_id == 1
        assert session.session_id == "test_session"
        
        # Test to_dict
        session_dict = session.to_dict()
        assert session_dict['id'] == 1
        assert session_dict['session_id'] == "test_session"
        
        # Test from_dict
        new_session = Session.from_dict(session_dict)
        assert new_session.id == 1
        assert new_session.session_id == "test_session"
        
        # Test is_expired
        assert session.is_expired() is False


# Integration Tests
class TestIntegration:
    """Integration tests for the complete system."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)
    
    def test_quantum_key_generation_integration(self):
        """Test complete quantum key generation workflow."""
        key_manager = KeyManager(storage_path=os.path.join(self.temp_dir, "keys"))
        quantum_generator = QuantumKeyGenerator(key_manager)
        
        # Generate key
        result = quantum_generator.generate_single_key("user1", "session1", num_bits=100)
        assert result['success'] is True
        assert 'key_id' in result
        assert 'key_length' in result
        
        # Retrieve key
        key = quantum_generator.get_key(result['key_id'])
        assert key is not None
        
        # Test key validity
        assert quantum_generator.is_key_valid(result['key_id']) is True
    
    def test_encryption_integration(self):
        """Test complete encryption workflow."""
        aes = AESEncryption()
        quantum_key = [0, 1, 0, 1, 0, 1, 0, 1] * 125  # 1000 bits
        
        # Encrypt message
        plaintext = "Hello, Quantum World!"
        encrypt_result = aes.encrypt(plaintext, quantum_key)
        assert encrypt_result['success'] is True
        
        # Decrypt message
        decrypt_result = aes.decrypt(
            encrypt_result['encrypted_data'],
            encrypt_result['iv'],
            quantum_key
        )
        assert decrypt_result['success'] is True
        assert decrypt_result['decrypted_data'] == plaintext
    
    def test_ml_classification_integration(self):
        """Test complete ML classification workflow."""
        temp_dir = os.path.join(self.temp_dir, "ml")
        model_manager = ModelManager(models_dir=temp_dir, data_dir=temp_dir)
        
        # Train model
        training_result = model_manager.train_model(samples_per_class=20)
        assert training_result['success'] is True
        
        # Test prediction
        features = {
            'key_length': 1000,
            'detection_probability': 0.1,
            'hamming_distance': 5,
            'key_entropy': 0.8,
            'transmission_success_rate': 0.95,
            'noise_level': 0.05,
            'protocol_success': 1,
            'eavesdropping_detected': 0,
            'error_rate': 0.02,
            'timing_anomaly': 0.1,
            'key_reuse_count': 0,
            'session_duration': 100
        }
        
        prediction = model_manager.predict_security_threat(features)
        assert prediction['success'] is True
        assert 'prediction_label' in prediction
        assert 'threat_level' in prediction


# Performance Tests
class TestPerformance:
    """Performance tests for critical components."""
    
    def test_quantum_protocol_performance(self):
        """Test quantum protocol performance."""
        import time
        
        start_time = time.time()
        protocol = BB84Protocol(num_bits=1000, enable_eavesdropping=False)
        result = protocol.run_protocol()
        end_time = time.time()
        
        assert result['success'] is True
        assert (end_time - start_time) < 5.0  # Should complete within 5 seconds
    
    def test_encryption_performance(self):
        """Test encryption performance."""
        import time
        
        aes = AESEncryption()
        quantum_key = [0, 1] * 500  # 1000 bits
        plaintext = "A" * 1000  # 1000 character message
        
        start_time = time.time()
        encrypt_result = aes.encrypt(plaintext, quantum_key)
        encrypt_time = time.time() - start_time
        
        start_time = time.time()
        decrypt_result = aes.decrypt(
            encrypt_result['encrypted_data'],
            encrypt_result['iv'],
            quantum_key
        )
        decrypt_time = time.time() - start_time
        
        assert encrypt_result['success'] is True
        assert decrypt_result['success'] is True
        assert encrypt_time < 1.0  # Encryption should be fast
        assert decrypt_time < 1.0  # Decryption should be fast
    
    def test_ml_training_performance(self):
        """Test ML training performance."""
        import time
        
        temp_dir = tempfile.mkdtemp()
        try:
            model_manager = ModelManager(models_dir=temp_dir, data_dir=temp_dir)
            
            start_time = time.time()
            result = model_manager.train_model(samples_per_class=50)
            training_time = time.time() - start_time
            
            assert result['success'] is True
            assert training_time < 30.0  # Training should complete within 30 seconds
        finally:
            shutil.rmtree(temp_dir)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
