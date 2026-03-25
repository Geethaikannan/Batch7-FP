import numpy as np

class QABNN:
    def __init__(self, threshold=10.50):
        self.normal_proto = None
        self.attack_proto = None
        self.threshold = threshold

    def binarize(self, X):
        return (X > 0).astype(np.uint8)

    def fit(self, X, y):
        X_bin = self.binarize(X)

        normal_samples = X_bin[y == 0]
        attack_samples = X_bin[y == 1]

        if len(normal_samples) == 0 or len(attack_samples) == 0:
            raise ValueError("Both classes must be present in training data.")

        self.normal_proto = np.mean(normal_samples, axis=0)
        self.attack_proto = np.mean(attack_samples, axis=0)

    def _compute_score(self, X):
        X_bin = self.binarize(X)

        normal_center = (self.normal_proto > 0.5).astype(np.uint8)
        attack_center = (self.attack_proto > 0.5).astype(np.uint8)

        normal_dist = np.sum(np.bitwise_xor(X_bin, normal_center), axis=1)
        attack_dist = np.sum(np.bitwise_xor(X_bin, attack_center), axis=1)

        return normal_dist - attack_dist

    def predict(self, X):
        score = self._compute_score(X)
        return (score < self.threshold).astype(int)

    def predict_proba(self, X):
        score = self._compute_score(X)

        # Convert to probability via sigmoid
        probs_attack = 1 / (1 + np.exp(score))

        # Return shape (n_samples, 2)
        return np.vstack([1 - probs_attack, probs_attack]).T
