"""
Model Manager for ML Operations

This module provides model management functionality including
training, evaluation, and deployment of security classifiers.
"""

import os
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from .security_classifier import SecurityClassifier
from .data_generator import DataGenerator


class ModelManager:
    """
    ModelManager class for managing ML models and operations.
    
    This class provides functionality for training, evaluating,
    and managing security classification models.
    """
    
    def __init__(self, models_dir: str = "models", data_dir: str = "data"):
        """
        Initialize the model manager.
        
        Args:
            models_dir: Directory for storing models
            data_dir: Directory for storing data
        """
        self.models_dir = models_dir
        self.data_dir = data_dir
        self.classifier = SecurityClassifier()
        self.data_generator = DataGenerator()
        
        # Ensure directories exist
        os.makedirs(models_dir, exist_ok=True)
        os.makedirs(data_dir, exist_ok=True)
        
        # Model metadata
        self.model_metadata = {}
        self.training_history = []
    
    def prepare_training_data(self, samples_per_class: int = 1000) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepare training data for model training.
        
        Args:
            samples_per_class: Number of samples per class
            
        Returns:
            Tuple of (features, labels)
        """
        # Generate training data if not exists
        training_data_path = os.path.join(self.data_dir, "training_data.csv")
        if not os.path.exists(training_data_path):
            print("Generating training data...")
            self.data_generator.output_path = training_data_path
            df = self.data_generator.generate_training_dataset(samples_per_class)
        else:
            df = pd.read_csv(training_data_path)
        
        # Prepare features and labels
        X = self.classifier.prepare_features(df)
        
        # Convert labels to numeric
        label_mapping = {'Normal': 0, 'Eavesdropping': 1, 'Noise': 2, 'Attack': 3}
        y = np.array([label_mapping[label] for label in df['label']])
        
        return X, y
    
    def train_model(self, samples_per_class: int = 1000, test_size: float = 0.2) -> Dict:
        """
        Train the security classifier model.
        
        Args:
            samples_per_class: Number of samples per class
            test_size: Test set size ratio
            
        Returns:
            Training results dictionary
        """
        try:
            print("Preparing training data...")
            X, y = self.prepare_training_data(samples_per_class)
            
            print("Training model...")
            training_result = self.classifier.train(X, y, test_size)
            
            if training_result['success']:
                # Record training metadata
                training_record = {
                    'timestamp': datetime.now().isoformat(),
                    'samples_per_class': samples_per_class,
                    'total_samples': len(X),
                    'test_size': test_size,
                    'train_score': training_result['train_score'],
                    'test_score': training_result['test_score'],
                    'cv_mean': training_result['cv_mean'],
                    'cv_std': training_result['cv_std']
                }
                
                self.training_history.append(training_record)
                
                # Save training history
                self._save_training_history()
                
                print(f"Model trained successfully!")
                print(f"Test accuracy: {training_result['test_score']:.4f}")
                print(f"Cross-validation mean: {training_result['cv_mean']:.4f}")
            
            return training_result
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Training failed: {str(e)}'
            }
    
    def evaluate_model(self, samples_per_class: int = 200) -> Dict:
        """
        Evaluate the trained model on validation data.
        
        Args:
            samples_per_class: Number of samples per class for validation
            
        Returns:
            Evaluation results dictionary
        """
        try:
            if not self.classifier.is_trained:
                return {
                    'success': False,
                    'error': 'Model not trained'
                }
            
            print("Preparing validation data...")
            # Generate validation data
            validation_data_path = os.path.join(self.data_dir, "validation_data.csv")
            self.data_generator.output_path = validation_data_path
            df = self.data_generator.generate_validation_dataset(samples_per_class)
            
            # Prepare features and labels
            X = self.classifier.prepare_features(df)
            label_mapping = {'Normal': 0, 'Eavesdropping': 1, 'Noise': 2, 'Attack': 3}
            y = np.array([label_mapping[label] for label in df['label']])
            
            print("Evaluating model...")
            evaluation_result = self.classifier.evaluate_model(X, y)
            
            if evaluation_result['success']:
                print(f"Validation accuracy: {evaluation_result['accuracy']:.4f}")
            
            return evaluation_result
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Evaluation failed: {str(e)}'
            }
    
    def predict_security_threat(self, features: Dict) -> Dict:
        """
        Predict security threat for given features.
        
        Args:
            features: Dictionary containing feature values
            
        Returns:
            Prediction results
        """
        if not self.classifier.is_trained:
            return {
                'success': False,
                'error': 'Model not trained'
            }
        
        return self.classifier.predict_security_threat(features)
    
    def batch_predict(self, data: List[Dict]) -> List[Dict]:
        """
        Make batch predictions on multiple data points.
        
        Args:
            data: List of feature dictionaries
            
        Returns:
            List of prediction results
        """
        if not self.classifier.is_trained:
            return [{'success': False, 'error': 'Model not trained'} for _ in data]
        
        results = []
        for features in data:
            result = self.classifier.predict_security_threat(features)
            results.append(result)
        
        return results
    
    def get_model_performance(self) -> Dict:
        """
        Get model performance metrics.
        
        Returns:
            Dictionary containing performance metrics
        """
        if not self.classifier.is_trained:
            return {'error': 'Model not trained'}
        
        model_info = self.classifier.get_model_info()
        feature_importance = self.classifier.get_feature_importance()
        
        return {
            'is_trained': model_info['is_trained'],
            'feature_names': model_info['feature_names'],
            'class_names': model_info['class_names'],
            'feature_importance': feature_importance,
            'training_history': self.training_history
        }
    
    def retrain_model(self, new_samples_per_class: int = 500) -> Dict:
        """
        Retrain the model with additional data.
        
        Args:
            new_samples_per_class: Number of new samples per class
            
        Returns:
            Retraining results
        """
        try:
            print("Retraining model with additional data...")
            
            # Generate additional training data
            additional_data = []
            additional_data.extend(self.data_generator.generate_normal_data(new_samples_per_class))
            additional_data.extend(self.data_generator.generate_eavesdropping_data(new_samples_per_class))
            additional_data.extend(self.data_generator.generate_noise_data(new_samples_per_class))
            additional_data.extend(self.data_generator.generate_attack_data(new_samples_per_class))
            
            # Convert to DataFrame
            df_additional = pd.DataFrame(additional_data)
            
            # Load existing training data
            existing_data_path = os.path.join(self.data_dir, "training_data.csv")
            if os.path.exists(existing_data_path):
                df_existing = pd.read_csv(existing_data_path)
                df_combined = pd.concat([df_existing, df_additional], ignore_index=True)
            else:
                df_combined = df_additional
            
            # Shuffle combined data
            df_combined = df_combined.sample(frac=1, random_state=42).reset_index(drop=True)
            
            # Save combined data
            df_combined.to_csv(existing_data_path, index=False)
            
            # Retrain model
            X = self.classifier.prepare_features(df_combined)
            label_mapping = {'Normal': 0, 'Eavesdropping': 1, 'Noise': 2, 'Attack': 3}
            y = np.array([label_mapping[label] for label in df_combined['label']])
            
            training_result = self.classifier.train(X, y)
            
            if training_result['success']:
                # Record retraining metadata
                retraining_record = {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'retraining',
                    'additional_samples_per_class': new_samples_per_class,
                    'total_samples': len(X),
                    'test_score': training_result['test_score'],
                    'cv_mean': training_result['cv_mean']
                }
                
                self.training_history.append(retraining_record)
                self._save_training_history()
            
            return training_result
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Retraining failed: {str(e)}'
            }
    
    def deploy_model(self, deployment_name: str) -> Dict:
        """
        Deploy the trained model for production use.
        
        Args:
            deployment_name: Name for the deployment
            
        Returns:
            Deployment results
        """
        try:
            if not self.classifier.is_trained:
                return {
                    'success': False,
                    'error': 'Model not trained'
                }
            
            # Create deployment directory
            deployment_dir = os.path.join(self.models_dir, deployment_name)
            os.makedirs(deployment_dir, exist_ok=True)
            
            # Save model with deployment name
            deployment_model_path = os.path.join(deployment_dir, "security_classifier.pkl")
            self.classifier.model_path = deployment_model_path
            self.classifier.save_model()
            
            # Save deployment metadata
            deployment_metadata = {
                'deployment_name': deployment_name,
                'timestamp': datetime.now().isoformat(),
                'model_info': self.classifier.get_model_info(),
                'training_history': self.training_history
            }
            
            metadata_path = os.path.join(deployment_dir, "deployment_metadata.json")
            with open(metadata_path, 'w') as f:
                json.dump(deployment_metadata, f, indent=2)
            
            return {
                'success': True,
                'deployment_name': deployment_name,
                'deployment_path': deployment_dir,
                'model_path': deployment_model_path
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Deployment failed: {str(e)}'
            }
    
    def load_deployed_model(self, deployment_name: str) -> Dict:
        """
        Load a deployed model.
        
        Args:
            deployment_name: Name of the deployment
            
        Returns:
            Loading results
        """
        try:
            deployment_dir = os.path.join(self.models_dir, deployment_name)
            model_path = os.path.join(deployment_dir, "security_classifier.pkl")
            
            if not os.path.exists(model_path):
                return {
                    'success': False,
                    'error': 'Deployment not found'
                }
            
            # Load model
            self.classifier.model_path = model_path
            success = self.classifier.load_model()
            
            if success:
                # Load deployment metadata
                metadata_path = os.path.join(deployment_dir, "deployment_metadata.json")
                if os.path.exists(metadata_path):
                    with open(metadata_path, 'r') as f:
                        deployment_metadata = json.load(f)
                    self.training_history = deployment_metadata.get('training_history', [])
                
                return {
                    'success': True,
                    'deployment_name': deployment_name,
                    'model_info': self.classifier.get_model_info()
                }
            else:
                return {
                    'success': False,
                    'error': 'Failed to load model'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'Loading failed: {str(e)}'
            }
    
    def _save_training_history(self):
        """Save training history to file."""
        history_path = os.path.join(self.models_dir, "training_history.json")
        with open(history_path, 'w') as f:
            json.dump(self.training_history, f, indent=2)
    
    def get_training_history(self) -> List[Dict]:
        """Get training history."""
        return self.training_history.copy()
    
    def get_deployment_list(self) -> List[str]:
        """Get list of available deployments."""
        if not os.path.exists(self.models_dir):
            return []
        
        deployments = []
        for item in os.listdir(self.models_dir):
            item_path = os.path.join(self.models_dir, item)
            if os.path.isdir(item_path) and os.path.exists(os.path.join(item_path, "security_classifier.pkl")):
                deployments.append(item)
        
        return deployments
