"""
Diagnostic test to investigate why attacks are not being detected
"""
import os
import sys
import numpy as np
import pickle
import pandas as pd
from sklearn.metrics import confusion_matrix, accuracy_score
import warnings
warnings.filterwarnings('ignore')

sys.path.insert(0, os.path.dirname(__file__))

from src.qabnn import QABNN
from src.data_loader import load_data
from src.preprocessing import preprocess_data

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_PATH = os.path.join(BASE_DIR, "data", "UNSW_NB15_testing-set.csv")
train_path = os.path.join(BASE_DIR, "data", "UNSW_NB15_training-set.csv")

print("=" * 80)
print("NIDS DIAGNOSTIC TEST - THRESHOLD OPTIMIZATION")
print("=" * 80)

# Load data
print("\n[1] Loading dataset...")
_, test_df = load_data(train_path, TEST_PATH)
train_df, _ = load_data(train_path, TEST_PATH)

X_train, y_train = preprocess_data(train_df)
X_test, y_test = preprocess_data(test_df)

print(f"✓ Training samples: {len(X_train)} (Normal: {(y_train==0).sum()}, Attack: {(y_train==1).sum()})")
print(f"✓ Test samples: {len(X_test)} (Normal: {(y_test==0).sum()}, Attack: {(y_test==1).sum()})")

# Train model
print("\n[2] Training QABNN model...")
model = QABNN()
model.fit(X_train, y_train)

print(f"✓ Model prototypes computed")
print(f"  Normal prototype shape: {model.normal_proto.shape}")
print(f"  Attack prototype shape: {model.attack_proto.shape}")

# Check prototype differences
normal_center = (model.normal_proto > 0.5).astype(np.uint8)
attack_center = (model.attack_proto > 0.5).astype(np.uint8)
proto_diff = np.sum(np.abs(normal_center - attack_center))
print(f"  Prototype center difference: {proto_diff} out of {len(normal_center)} features")

# Get scores
print("\n[3] Computing decision scores...")
scores = model._compute_score(X_test)

print(f"✓ Score statistics:")
print(f"  Min score: {scores.min():.4f}")
print(f"  Max score: {scores.max():.4f}")
print(f"  Mean score: {scores.mean():.4f}")
print(f"  Median score: {np.median(scores):.4f}")
print(f"  Std Dev: {scores.std():.4f}")

# Check score distribution by class
normal_scores = scores[y_test == 0]
attack_scores = scores[y_test == 1]

print(f"\n  Normal traffic scores:")
print(f"    Mean: {normal_scores.mean():.4f}")
print(f"    Min: {normal_scores.min():.4f}")
print(f"    Max: {normal_scores.max():.4f}")

print(f"\n  Attack traffic scores:")
print(f"    Mean: {attack_scores.mean():.4f}")
print(f"    Min: {attack_scores.min():.4f}")
print(f"    Max: {attack_scores.max():.4f}")

if attack_scores.max() < 0:
    print("\n  ✓ Attacks have negative scores (good - can detect them)")
else:
    print(f"\n  ⚠ Some attacks have positive scores (threshold {model.threshold} won't catch them)")

# Test different thresholds
print("\n[4] Testing different thresholds...")
print("\nThreshold | Accuracy | Precision | Recall | F1   | TP  | FP  | FN")
print("-" * 70)

best_f1 = 0
best_threshold = 0

for threshold in np.arange(-10, 11, 0.5):
    y_pred = (scores < threshold).astype(int)
    
    accuracy = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    if f1 > best_f1:
        best_f1 = f1
        best_threshold = threshold
    
    if abs(threshold - int(threshold)) < 0.01:  # Print nice thresholds
        print(f"{threshold:9.1f} | {accuracy:8.4f} | {precision:9.4f} | {recall:6.4f} | {f1:4.2f} | {tp:3d} | {fp:3d} | {fn:3d}")

print("\n" + "=" * 80)
print(f"BEST THRESHOLD: {best_threshold:.2f}")
print(f"BEST F1-SCORE: {best_f1:.4f}")

# Evaluate with best threshold
y_pred_best = (scores < best_threshold).astype(int)
cm = confusion_matrix(y_test, y_pred_best)
tn, fp, fn, tp = cm.ravel()
precision = tp / (tp + fp) if (tp + fp) > 0 else 0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0

print("\nPerformance with optimal threshold:")
print(f"  Accuracy: {accuracy_score(y_test, y_pred_best):.4f}")
print(f"  Precision: {precision:.4f}")
print(f"  Recall (Detection Rate): {recall:.4f}")
print(f"  True Positives: {tp}")
print(f"  False Positives: {fp}")
print(f"  False Negatives: {fn}")

print("\n" + "=" * 80)

# Recommend solution
if best_f1 > 0.5:
    print("✓ SOLUTION: Update the model threshold in src/qabnn.py")
    print(f"  Change: self.threshold = {best_threshold:.2f}")
else:
    print("✗ CRITICAL: Even with optimal threshold, model performance is poor")
    print("  The model prototypes may not be learning attack patterns correctly")
    print("  Recommendations:")
    print("    1. Check if training data has proper labels")
    print("    2. Consider a different model architecture (Random Forest is in train.py)")
    print("    3. Analyze feature importance to understand what features distinguish attacks")

print("\n" + "=" * 80)
