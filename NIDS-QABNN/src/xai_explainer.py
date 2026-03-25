"""
XAI (Explainable AI) Module for QABNN Model
Provides explanations for why a sample is classified as attack or normal traffic
"""

import numpy as np
from typing import Dict, List, Tuple, Any


class QABNNExplainer:
    """
    Explains QABNN predictions by analyzing feature contributions
    and distances from attack/normal prototypes
    """
    
    def __init__(self, model, feature_names: List[str] = None):
        """
        Initialize the explainer
        
        Args:
            model: Trained QABNN model
            feature_names: Names of features (optional)
        """
        self.model = model
        self.feature_names = feature_names or [f"Feature_{i}" for i in range(43)]
        self.normal_proto = model.normal_proto
        self.attack_proto = model.attack_proto
    
    def _binarize(self, X):
        """Convert features to binary representation"""
        return (X > 0).astype(np.uint8)
    
    def _compute_distances(self, X_sample: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Compute distances from both prototypes
        
        Returns:
            normal_dist: XOR distance to normal prototype per feature
            attack_dist: XOR distance to attack prototype per feature
            pred_label: Prediction (0=normal, 1=attack)
        """
        X_bin = self._binarize(X_sample)
        normal_center = (self.normal_proto > 0.5).astype(np.uint8)
        attack_center = (self.attack_proto > 0.5).astype(np.uint8)
        
        # Per-feature XOR distance
        normal_dist = np.bitwise_xor(X_bin[0], normal_center)
        attack_dist = np.bitwise_xor(X_bin[0], attack_center)
        
        # Prediction
        total_normal = np.sum(normal_dist)
        total_attack = np.sum(attack_dist)
        pred_label = 1 if (total_normal - total_attack) < self.model.threshold else 0
        
        return normal_dist, attack_dist, pred_label
    
    def _get_confidence_score(self, X_sample: np.ndarray) -> Tuple[float, float]:
        """
        Calculate confidence scores for the prediction
        
        Returns:
            confidence: 0-1 confidence score
            diff: difference between normal and attack distances
        """
        X_bin = self._binarize(X_sample)
        normal_center = (self.normal_proto > 0.5).astype(np.uint8)
        attack_center = (self.attack_proto > 0.5).astype(np.uint8)
        
        total_normal = np.sum(np.bitwise_xor(X_bin[0], normal_center))
        total_attack = np.sum(np.bitwise_xor(X_bin[0], attack_center))
        
        diff = abs(total_normal - total_attack)
        # Normalize confidence (0-1)
        confidence = min(1.0, diff / max(1, 23))  # Assuming ~23 features
        
        return confidence, diff
    
    def _get_top_discriminative_features(self, 
                                         normal_dist: np.ndarray, 
                                         attack_dist: np.ndarray,
                                         top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Identify top features that discriminate between normal and attack
        
        Args:
            normal_dist: Per-feature distance to normal prototype
            attack_dist: Per-feature distance to attack prototype
            top_k: Number of top features to return
            
        Returns:
            List of features with their distances and description
        """
        # Features where distance differs most between normal and attack
        diff = np.abs(normal_dist.astype(int) - attack_dist.astype(int))
        top_indices = np.argsort(-diff)[:top_k]
        
        features = []
        for idx in top_indices:
            features.append({
                'feature': self.feature_names[idx],
                'index': int(idx),
                'distance_to_normal': int(normal_dist[idx]),
                'distance_to_attack': int(attack_dist[idx]),
                'discriminative_score': float(diff[idx])
            })
        
        return features
    
    def explain_prediction(self, X_sample: np.ndarray, 
                          sample_metadata: Dict = None) -> Dict[str, Any]:
        """
        Generate a comprehensive explanation for a prediction
        
        Args:
            X_sample: Feature vector (shape: 1 x n_features)
            sample_metadata: Additional metadata about the sample (proto, service, etc)
            
        Returns:
            Dictionary with detailed explanation
        """
        # Get prediction basics
        pred_label = self.model.predict(X_sample)[0]
        pred_proba = self.model.predict_proba(X_sample)[0]
        confidence, diff_score = self._get_confidence_score(X_sample)
        
        # Get distances
        normal_dist, attack_dist, _ = self._compute_distances(X_sample)
        
        # Get top discriminative features
        top_features = self._get_top_discriminative_features(normal_dist, attack_dist, top_k=5)
        
        # Generate reasoning
        reasoning = self._generate_reasoning(pred_label, confidence, diff_score, 
                                            top_features, sample_metadata)
        
        explanation = {
            'prediction': 'ATTACK' if pred_label == 1 else 'NORMAL',
            'confidence': round(confidence, 4),
            'confidence_percentage': round(confidence * 100, 2),
            'probability_normal': round(pred_proba[0], 4),
            'probability_attack': round(pred_proba[1], 4),
            'distance_difference': diff_score,
            'top_discriminative_features': top_features,
            'reasoning': reasoning,
            'metadata': sample_metadata or {}
        }
        
        return explanation
    
    def _generate_reasoning(self, pred_label: int, confidence: float, diff_score: float,
                           top_features: List[Dict], metadata: Dict = None) -> str:
        """Generate human-readable reasoning for the prediction"""
        
        pred_text = "ATTACK traffic" if pred_label == 1 else "NORMAL traffic"
        confidence_text = f"{confidence*100:.1f}% confidence"
        
        if confidence < 0.3:
            confidence_desc = "low confidence"
        elif confidence < 0.6:
            confidence_desc = "moderate confidence"
        elif confidence < 0.8:
            confidence_desc = "high confidence"
        else:
            confidence_desc = "very high confidence"
        
        # Build reasoning message
        reason_parts = []
        reason_parts.append(f"This is classified as {pred_text} with {confidence_desc} ({confidence_text}).")
        
        if top_features:
            feature_desc = self._describe_features(pred_label, top_features)
            reason_parts.append(f"Key indicators: {feature_desc}")
        
        # Add metadata-based reasoning
        if metadata:
            meta_reason = self._describe_metadata(pred_label, metadata)
            if meta_reason:
                reason_parts.append(meta_reason)
        
        return " ".join(reason_parts)
    
    def _describe_features(self, pred_label: int, top_features: List[Dict]) -> str:
        """Generate description of key features"""
        if not top_features:
            return "Pattern matches typical behavior."
        
        # Extract interesting features
        descriptions = []
        for feat in top_features[:3]:
            fname = feat['feature']
            if pred_label == 1:
                # For attacks, highlight features different from normal
                descriptions.append(f"{fname}")
            else:
                # For normal, highlight features consistent with normal
                descriptions.append(f"{fname}")
        
        return ", ".join(descriptions) + " show patterns consistent with " + \
               ("attack" if pred_label == 1 else "normal") + " traffic."
    
    def _describe_metadata(self, pred_label: int, metadata: Dict) -> str:
        """Generate description based on metadata"""
        if not metadata:
            return ""
        
        descriptions = []
        
        # Analyze attack category
        if pred_label == 1 and 'attack_cat' in metadata:
            cat = metadata.get('attack_cat')
            if cat and cat != 'Normal':
                descriptions.append(f"Detected as {cat} attack category.")
        
        # Analyze service/protocol
        service = metadata.get('service', 'unknown')
        proto = metadata.get('proto', 'unknown')
        if service != 'unknown':
            descriptions.append(f"Service: {service}")
        
        return " ".join(descriptions) if descriptions else ""
    
    def compare_samples(self, X_sample1: np.ndarray, X_sample2: np.ndarray,
                       label1: str = "Sample 1", label2: str = "Sample 2") -> Dict:
        """
        Compare two samples and explain their differences
        
        Args:
            X_sample1: First sample
            X_sample2: Second sample
            label1: Label for first sample
            label2: Label for second sample
            
        Returns:
            Comparison analysis
        """
        pred1 = self.model.predict(X_sample1)[0]
        pred2 = self.model.predict(X_sample2)[0]
        
        normal_dist1, attack_dist1, _ = self._compute_distances(X_sample1)
        normal_dist2, attack_dist2, _ = self._compute_distances(X_sample2)
        
        # Find most different features
        feature_diff = np.abs((normal_dist1 - normal_dist2).astype(int) + 
                             (attack_dist1 - attack_dist2).astype(int))
        top_diff_indices = np.argsort(-feature_diff)[:5]
        
        comparison = {
            'label1': label1,
            'label2': label2,
            'pred1': 'ATTACK' if pred1 == 1 else 'NORMAL',
            'pred2': 'ATTACK' if pred2 == 1 else 'NORMAL',
            'most_different_features': [
                {
                    'feature': self.feature_names[idx],
                    'sample1_distance_normal': int(normal_dist1[idx]),
                    'sample2_distance_normal': int(normal_dist2[idx]),
                    'sample1_distance_attack': int(attack_dist1[idx]),
                    'sample2_distance_attack': int(attack_dist2[idx]),
                }
                for idx in top_diff_indices
            ]
        }
        
        return comparison


class FeatureImportanceCalculator:
    """Calculate feature importance using different methods"""
    
    @staticmethod
    def calculate_binary_importance(normal_proto: np.ndarray, 
                                   attack_proto: np.ndarray,
                                   feature_names: List[str] = None) -> List[Dict]:
        """
        Calculate feature importance based on prototype differences
        
        Args:
            normal_proto: Normal prototype
            attack_proto: Attack prototype
            feature_names: Feature names
            
        Returns:
            List of features ranked by importance
        """
        importance = np.abs(normal_proto - attack_proto)
        sorted_indices = np.argsort(-importance)
        
        if feature_names is None:
            feature_names = [f"Feature_{i}" for i in range(len(importance))]
        
        results = []
        for rank, idx in enumerate(sorted_indices):
            results.append({
                'rank': rank + 1,
                'feature': feature_names[idx],
                'importance': float(importance[idx]),
                'normal_proto': float(normal_proto[idx]),
                'attack_proto': float(attack_proto[idx])
            })
        
        return results
    
    @staticmethod
    def calculate_sample_importance(X_sample: np.ndarray,
                                   feature_names: List[str] = None) -> List[Dict]:
        """
        Calculate which features are most active in a sample
        
        Args:
            X_sample: Feature vector
            feature_names: Feature names
            
        Returns:
            List of features ranked by activation
        """
        X_bin = (X_sample[0] > 0).astype(np.uint8)
        
        if feature_names is None:
            feature_names = [f"Feature_{i}" for i in range(len(X_sample[0]))]
        
        results = []
        for idx in np.argsort(-X_bin):
            results.append({
                'feature': feature_names[idx],
                'value': float(X_sample[0, idx]),
                'active': int(X_bin[idx])
            })
        
        return results
