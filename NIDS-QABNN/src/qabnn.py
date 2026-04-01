import numpy as np

class QABNN:
    def __init__(self, threshold=None):
        self.normal_proto = None
        self.attack_proto = None
        self.threshold = threshold
        self.std_normal = None
        self.std_attack = None

    def binarize(self, X):
        """Convert features to binary (0/1)"""
        return (X > 0).astype(np.float32)

    def fit(self, X, y):
        """Train the model on binary encoded features"""
        X_bin = self.binarize(X)

        normal_samples = X_bin[y == 0]
        attack_samples = X_bin[y == 1]

        if len(normal_samples) == 0 or len(attack_samples) == 0:
            raise ValueError("Both classes must be present in training data.")

        # Prototypes as mean of each class
        self.normal_proto = np.mean(normal_samples, axis=0)
        self.attack_proto = np.mean(attack_samples, axis=0)
        
        # Calculate dot product scores for each class
        normal_scores = np.dot(normal_samples, self.attack_proto)
        attack_scores = np.dot(attack_samples, self.attack_proto)
        
        # Set threshold at midpoint
        mean_normal = np.mean(normal_scores)
        mean_attack = np.mean(attack_scores)
        
        if self.threshold is None:
            self.threshold = (mean_normal + mean_attack) / 2.0
        
        self.std_normal = np.std(normal_scores)
        self.std_attack = np.std(attack_scores)

    def _compute_score(self, X):
        """Compute attack-likelihood score"""
        X_bin = self.binarize(X)
        # Score = dot product with attack prototype
        return np.dot(X_bin, self.attack_proto)

    def predict(self, X):
        score = self._compute_score(X)
        return (score > self.threshold).astype(int)

    def predict_proba(self, X):
        """Calculate probability scores"""
        score = self._compute_score(X)
        
        # Normalize to [0, 1] using sigmoid
        shifted = (score - self.threshold)
        
        # Use standard sigmoid with scale factor
        scale = 1.0
        if hasattr(self, 'std_attack') and hasattr(self, 'std_normal'):
            if self.std_attack and self.std_normal:
                scale = max(self.std_attack, self.std_normal)
            
        if scale == 0:
            scale = 1.0
            
        shifted_clipped = np.clip(shifted / (scale + 1e-6), -10, 10)
        probs_attack = 1.0 / (1.0 + np.exp(-shifted_clipped))
        
        return np.vstack([1 - probs_attack, probs_attack]).T
