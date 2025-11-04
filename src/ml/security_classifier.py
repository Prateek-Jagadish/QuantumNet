"""
Security Classifier using RandomForest

This module implements a RandomForest classifier for security monitoring
and threat detection in quantum communication systems.
"""

import os
import pickle
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Union
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib


class SecurityClassifier:
    """
    SecurityClassifier class implementing RandomForest for security monitoring.
    
    This class provides threat detection, anomaly detection, and security
    classification for quantum communication systems.
    """
    
    def __init__(self, model_path: str = "models/security_classifier.pkl"):
        """
        Initialize the security classifier.
        
        Args:
            model_path: Path to save/load the trained model
        """
        self.model_path = model_path
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = []
        self.class_names = ['Normal', 'Eavesdropping', 'Noise', 'Attack']
        
        # Ensure models directory exists
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    def prepare_features(self, data: pd.DataFrame) -> np.ndarray:
        """
        Prepare features for training/prediction.
        
        Args:
            data: DataFrame containing raw data
            
        Returns:
            Prepared feature array
        """
        # Select relevant features
        feature_columns = [
            'key_length', 'detection_probability', 'hamming_distance',
            'key_entropy', 'transmission_success_rate', 'noise_level',
            'protocol_success', 'eavesdropping_detected', 'error_rate',
            'timing_anomaly', 'key_reuse_count', 'session_duration'
        ]
        
        # Filter available features
        available_features = [col for col in feature_columns if col in data.columns]
        
        if not available_features:
            raise ValueError("No valid features found in data")
        
        # Extract features
        features = data[available_features].fillna(0).values
        
        # Store feature names for later use
        self.feature_names = available_features
        
        return features
    
    def train(self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2) -> Dict:
        """
        Train the RandomForest classifier.
        
        Args:
            X: Feature matrix
            y: Target labels
            test_size: Test set size ratio
            
        Returns:
            Training results dictionary
        """
        try:
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=42, stratify=y
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train model
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate model
            train_score = self.model.score(X_train_scaled, y_train)
            test_score = self.model.score(X_test_scaled, y_test)
            
            # Cross-validation
            cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=5)
            
            # Predictions
            y_pred = self.model.predict(X_test_scaled)
            
            # Classification report
            class_report = classification_report(y_test, y_pred, output_dict=True)
            
            # Confusion matrix
            conf_matrix = confusion_matrix(y_test, y_pred)
            
            self.is_trained = True
            
            # Save model
            self.save_model()
            
            return {
                'success': True,
                'train_score': train_score,
                'test_score': test_score,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'classification_report': class_report,
                'confusion_matrix': conf_matrix.tolist(),
                'feature_importance': self.get_feature_importance()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Make predictions on new data.
        
        Args:
            X: Feature matrix
            
        Returns:
            Predicted labels
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Get prediction probabilities.
        
        Args:
            X: Feature matrix
            
        Returns:
            Prediction probabilities
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)
    
    def predict_security_threat(self, features: Dict) -> Dict:
        """
        Predict security threat level for a single instance.
        
        Args:
            features: Dictionary containing feature values
            
        Returns:
            Prediction results
        """
        try:
            if not self.is_trained:
                return {
                    'success': False,
                    'error': 'Model not trained'
                }
            
            # Convert features to array
            feature_array = np.array([[
                features.get('key_length', 0),
                features.get('detection_probability', 0),
                features.get('hamming_distance', 0),
                features.get('key_entropy', 0),
                features.get('transmission_success_rate', 1),
                features.get('noise_level', 0),
                features.get('protocol_success', 1),
                features.get('eavesdropping_detected', 0),
                features.get('error_rate', 0),
                features.get('timing_anomaly', 0),
                features.get('key_reuse_count', 0),
                features.get('session_duration', 0)
            ]])
            
            # Make prediction
            prediction = self.predict(feature_array)[0]
            probabilities = self.predict_proba(feature_array)[0]
            
            # Get threat level
            threat_level = self._get_threat_level(prediction, probabilities)
            
            return {
                'success': True,
                'prediction': prediction,
                'prediction_label': self.class_names[prediction],
                'probabilities': {
                    self.class_names[i]: prob for i, prob in enumerate(probabilities)
                },
                'threat_level': threat_level,
                'confidence': max(probabilities),
                'recommendation': self._get_recommendation(prediction, threat_level)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_feature_importance(self) -> Dict:
        """
        Get feature importance from the trained model.
        
        Returns:
            Dictionary of feature importance
        """
        if not self.is_trained:
            return {}
        
        importance = self.model.feature_importances_
        return {
            self.feature_names[i]: importance[i] 
            for i in range(len(self.feature_names))
        }
    
    def _get_threat_level(self, prediction: int, probabilities: np.ndarray) -> str:
        """Get threat level based on prediction and confidence."""
        if prediction == 0:  # Normal
            return "LOW"
        elif prediction == 1:  # Eavesdropping
            return "HIGH" if probabilities[prediction] > 0.8 else "MEDIUM"
        elif prediction == 2:  # Noise
            return "MEDIUM" if probabilities[prediction] > 0.7 else "LOW"
        else:  # Attack
            return "CRITICAL" if probabilities[prediction] > 0.9 else "HIGH"
    
    def _get_recommendation(self, prediction: int, threat_level: str) -> str:
        """Get security recommendation based on prediction."""
        recommendations = {
            0: "Continue normal operation",
            1: "Regenerate quantum keys and investigate potential eavesdropping",
            2: "Check channel conditions and consider noise reduction",
            3: "Immediate security response required - potential active attack"
        }
        
        base_recommendation = recommendations.get(prediction, "Unknown threat type")
        
        if threat_level == "CRITICAL":
            return f"URGENT: {base_recommendation}"
        elif threat_level == "HIGH":
            return f"High Priority: {base_recommendation}"
        else:
            return base_recommendation
    
    def save_model(self) -> bool:
        """
        Save the trained model to disk.
        
        Returns:
            True if successful
        """
        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names,
                'class_names': self.class_names,
                'is_trained': self.is_trained
            }
            
            with open(self.model_path, 'wb') as f:
                pickle.dump(model_data, f)
            
            return True
            
        except Exception as e:
            print(f"Error saving model: {e}")
            return False
    
    def load_model(self) -> bool:
        """
        Load a trained model from disk.
        
        Returns:
            True if successful
        """
        try:
            if not os.path.exists(self.model_path):
                return False
            
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            self.class_names = model_data['class_names']
            self.is_trained = model_data['is_trained']
            
            return True
            
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
    
    def evaluate_model(self, X: np.ndarray, y: np.ndarray) -> Dict:
        """
        Evaluate the model on test data.
        
        Args:
            X: Feature matrix
            y: True labels
            
        Returns:
            Evaluation results
        """
        if not self.is_trained:
            return {'success': False, 'error': 'Model not trained'}
        
        try:
            X_scaled = self.scaler.transform(X)
            y_pred = self.model.predict(X_scaled)
            
            accuracy = accuracy_score(y, y_pred)
            class_report = classification_report(y, y_pred, output_dict=True)
            conf_matrix = confusion_matrix(y, y_pred)
            
            return {
                'success': True,
                'accuracy': accuracy,
                'classification_report': class_report,
                'confusion_matrix': conf_matrix.tolist()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_model_info(self) -> Dict:
        """
        Get information about the current model.
        
        Returns:
            Model information dictionary
        """
        return {
            'is_trained': self.is_trained,
            'model_path': self.model_path,
            'feature_names': self.feature_names,
            'class_names': self.class_names,
            'n_estimators': self.model.n_estimators,
            'max_depth': self.model.max_depth,
            'random_state': self.model.random_state
        }
