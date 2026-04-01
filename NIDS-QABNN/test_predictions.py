#!/usr/bin/env python3
"""
Test script to verify QABNN predictions are working correctly
"""
import os
import pickle
import numpy as np
import logging
from src.data_loader import load_data
from src.preprocessing import preprocess_data

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_PATH = os.path.join(BASE_DIR, "data", "UNSW_NB15_testing-set.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "qabnn_model.pkl")

def main():
    print("\n" + "="*80)
    print("QABNN PREDICTION TEST")
    print("="*80)
    
    # Load test data
    print("\n[1] Loading test data...")
    _, test_df = load_data(TEST_PATH, TEST_PATH)
    
    # Preprocess
    print("[2] Preprocessing test data...")
    X_test, y_test = preprocess_data(test_df)
    y_test = np.array(y_test)
    
    print(f"    - Test samples: {len(X_test)}")
    print(f"    - Normal samples: {(y_test == 0).sum()}")
    print(f"    - Attack samples: {(y_test == 1).sum()}")
    
    # Load model
    print("\n[3] Loading trained QABNN model...")
    if not os.path.exists(MODEL_PATH):
        print(f"    ERROR: Model not found at {MODEL_PATH}")
        return
    
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    print("    Model loaded successfully")
    
    # Make predictions
    print("\n[4] Making predictions on test data...")
    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)
    
    print(f"    - Predicted attacks: {(predictions == 1).sum()}")
    print(f"    - Predicted normal: {(predictions == 0).sum()}")
    
    # Analyze confidence scores
    print("\n[5] Analyzing confidence scores...")
    
    # For attacks
    attack_probs = probabilities[predictions == 1, 1]  # Attack probability for predicted attacks
    if len(attack_probs) > 0:
        print(f"\n    Predicted ATTACKS:")
        print(f"      - Count: {len(attack_probs)}")
        print(f"      - Mean confidence: {np.mean(attack_probs)*100:.2f}%")
        print(f"      - Min confidence: {np.min(attack_probs)*100:.2f}%")
        print(f"      - Max confidence: {np.max(attack_probs)*100:.2f}%")
        print(f"      - Std confidence: {np.std(attack_probs)*100:.2f}%")
    else:
        print(f"\n    Predicted ATTACKS: NONE")
    
    # For normal
    normal_probs = probabilities[predictions == 0, 0]  # Normal probability for predicted normal
    if len(normal_probs) > 0:
        print(f"\n    Predicted NORMAL:")
        print(f"      - Count: {len(normal_probs)}")
        print(f"      - Mean confidence: {np.mean(normal_probs)*100:.2f}%")
        print(f"      - Min confidence: {np.min(normal_probs)*100:.2f}%")
        print(f"      - Max confidence: {np.max(normal_probs)*100:.2f}%")
        print(f"      - Std confidence: {np.std(normal_probs)*100:.2f}%")
    else:
        print(f"\n    Predicted NORMAL: NONE")
    
    # Sample predictions
    print("\n[6] Sample predictions (first 10 test samples):")
    print(f"\n{'True Label':<15} {'Prediction':<15} {'Normal Prob':<15} {'Attack Prob':<15}")
    print("-" * 60)
    
    for i in range(min(10, len(X_test))):
        true_label = "Normal" if y_test[i] == 0 else "Attack"
        pred_label = "Normal" if predictions[i] == 0 else "Attack"
        normal_prob = probabilities[i, 0] * 100
        attack_prob = probabilities[i, 1] * 100
        print(f"{true_label:<15} {pred_label:<15} {normal_prob:<14.2f}% {attack_prob:<14.2f}%")
    
    # Accuracy on first 100 samples
    print("\n[7] Accuracy on first 100 test samples:")
    first_100_acc = np.mean(predictions[:100] == y_test[:100])
    print(f"    - Accuracy: {first_100_acc*100:.2f}%")
    
    # Show examples of actual attacks detected
    attack_indices = np.where((predictions == 1) & (y_test == 1))[0]  # True positives
    if len(attack_indices) > 0:
        print(f"\n[8] Examples of correctly detected attacks (True Positives):")
        print(f"    - Count: {len(attack_indices)}")
        if len(attack_indices) > 0:
            idx = attack_indices[0]
            print(f"    - First example (index {idx}):")
            print(f"      - Attack probability: {probabilities[idx, 1]*100:.2f}%")
    else:
        print(f"\n[8] No attacks correctly detected in first samples")
    
    print("\n" + "="*80)
    print("TEST COMPLETE")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
