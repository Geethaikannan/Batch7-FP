"""
Attack Detection Test - Comprehensive evaluation of the NIDS system
Tests the model's ability to detect various types of attacks from UNSW-NB15 dataset
"""
import os
import sys
import numpy as np
import pickle
import pandas as pd
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score, precision_score, recall_score, f1_score
import warnings
warnings.filterwarnings('ignore')

# Add project to path
sys.path.insert(0, os.path.dirname(__file__))

from src.qabnn import QABNN
from src.data_loader import load_data
from src.preprocessing import preprocess_data

def run_attack_detection_test():
    """Run comprehensive attack detection test"""
    
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    TEST_PATH = os.path.join(BASE_DIR, "data", "UNSW_NB15_testing-set.csv")
    train_path = os.path.join(BASE_DIR, "data", "UNSW_NB15_training-set.csv")
    
    print("=" * 80)
    print("NIDS ATTACK DETECTION TEST")
    print("=" * 80)
    
    # Load data
    print("\n[1] Loading dataset...")
    _, test_df = load_data(train_path, TEST_PATH)
    X_test, y_test = preprocess_data(test_df)
    print(f"✓ Test dataset loaded: {len(test_df)} samples")
    print(f"  Features: {X_test.shape[1]}")
    
    # Load or train model
    print("\n[2] Loading model...")
    model_path = os.path.join(BASE_DIR, "models", "qabnn_model.pkl")
    
    if os.path.exists(model_path):
        try:
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            print("✓ Pre-trained model loaded")
        except:
            print("⚠ Could not load model, training new one...")
            train_df, _ = load_data(train_path, TEST_PATH)
            X_train, y_train = preprocess_data(train_df)
            model = QABNN()
            model.fit(X_train, y_train)
            print("✓ Model trained")
    else:
        print("⚠ Training new model...")
        train_df, _ = load_data(train_path, TEST_PATH)
        X_train, y_train = preprocess_data(train_df)
        model = QABNN()
        model.fit(X_train, y_train)
        print("✓ Model trained")
    
    # Make predictions
    print("\n[3] Making predictions on test data...")
    y_pred = model.predict(X_test)
    print(f"✓ Predictions complete")
    
    # Overall metrics
    print("\n" + "=" * 80)
    print("OVERALL PERFORMANCE METRICS")
    print("=" * 80)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    
    print(f"\nAccuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1-Score:  {f1:.4f}")
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    print(f"\nConfusion Matrix:")
    print(f"  True Negatives:  {tn} (correctly identified normal traffic)")
    print(f"  False Positives: {fp} (normal traffic wrongly identified as attack)")
    print(f"  False Negatives: {fn} (attacks missed - DANGEROUS!)")
    print(f"  True Positives:  {tp} (correctly detected attacks)")
    
    # Attack detection rate
    if (tn + fn) > 0:
        false_positive_rate = fp / (tn + fp) if (tn + fp) > 0 else 0
        print(f"\nFalse Positive Rate: {false_positive_rate:.4f} ({false_positive_rate*100:.2f}%)")
    
    if (tp + fn) > 0:
        detection_rate = tp / (tp + fn)
        print(f"Attack Detection Rate: {detection_rate:.4f} ({detection_rate*100:.2f}%)")
        print(f"Missed Attacks: {fn} out of {tp + fn}")
    
    # Detailed report
    print("\n" + "=" * 80)
    print("DETAILED CLASSIFICATION REPORT")
    print("=" * 80)
    print("\n" + classification_report(y_test, y_pred, target_names=['Normal', 'Attack'], zero_division=0))
    
    # Attack types analysis
    print("\n" + "=" * 80)
    print("ATTACK TYPE BREAKDOWN")
    print("=" * 80)
    
    if 'attack_cat' in test_df.columns:
        attack_df = test_df[y_test == 1].copy()
        attack_df['pred'] = y_pred[y_test == 1]
        
        if len(attack_df) > 0:
            for attack_type in attack_df['attack_cat'].unique():
                if pd.isna(attack_type):
                    continue
                attack_type_data = attack_df[attack_df['attack_cat'] == attack_type]
                detected = (attack_type_data['pred'] == 1).sum()
                total = len(attack_type_data)
                detection_pct = (detected / total * 100) if total > 0 else 0
                
                print(f"\n{attack_type}:")
                print(f"  Total: {total}")
                print(f"  Detected: {detected}")
                print(f"  Detection Rate: {detection_pct:.2f}%")
                print(f"  Missed: {total - detected}")
    
    # Sample detections
    print("\n" + "=" * 80)
    print("SAMPLE DETECTIONS (CORRECTLY IDENTIFIED ATTACKS)")
    print("=" * 80)
    
    correct_detections = (y_test == 1) & (y_pred == 1)
    if correct_detections.sum() > 0:
        print(f"\nShowing first 5 correctly detected attacks:")
        correct_indices = np.where(correct_detections)[0][:5]
        for idx in correct_indices:
            row = test_df.iloc[idx]
            print(f"\n  Sample {idx + 1}:")
            print(f"    Attack Type: {row.get('attack_cat', 'Unknown')}")
            print(f"    Protocol: {row.get('proto', 'N/A')}")
            print(f"    Service: {row.get('service', 'N/A')}")
            print(f"    Src Bytes: {row.get('sbytes', 0)}, Dst Bytes: {row.get('dbytes', 0)}")
    
    # Sample missed detections
    print("\n" + "=" * 80)
    print("SAMPLE MISSED DETECTIONS (ATTACKS NOT DETECTED)")
    print("=" * 80)
    
    missed_attacks = (y_test == 1) & (y_pred == 0)
    if missed_attacks.sum() > 0:
        print(f"\n⚠ Found {missed_attacks.sum()} missed attacks!")
        print(f"Showing first 5 missed attacks:")
        missed_indices = np.where(missed_attacks)[0][:5]
        for idx in missed_indices:
            row = test_df.iloc[idx]
            print(f"\n  Sample {idx + 1}:")
            print(f"    Attack Type: {row.get('attack_cat', 'Unknown')}")
            print(f"    Protocol: {row.get('proto', 'N/A')}")
            print(f"    Service: {row.get('service', 'N/A')}")
            print(f"    Src Bytes: {row.get('sbytes', 0)}, Dst Bytes: {row.get('dbytes', 0)}")
    else:
        print("\n✓ No missed attacks - Perfect detection!")
    
    # Test results summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    if detection_rate >= 0.95:
        print(f"\n✓ EXCELLENT: System detects {detection_rate*100:.2f}% of attacks!")
    elif detection_rate >= 0.85:
        print(f"\n✓ GOOD: System detects {detection_rate*100:.2f}% of attacks")
    elif detection_rate >= 0.70:
        print(f"\n⚠ ACCEPTABLE: System detects {detection_rate*100:.2f}% of attacks (room for improvement)")
    else:
        print(f"\n✗ POOR: System detects only {detection_rate*100:.2f}% of attacks (needs improvement)")
    
    if false_positive_rate < 0.01:
        print(f"✓ LOW false positive rate: {false_positive_rate*100:.2f}%")
    elif false_positive_rate < 0.05:
        print(f"✓ Acceptable false positive rate: {false_positive_rate*100:.2f}%")
    else:
        print(f"⚠ High false positive rate: {false_positive_rate*100:.2f}%")
    
    print("\n" + "=" * 80)
    print("END OF ATTACK DETECTION TEST")
    print("=" * 80)
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'detection_rate': detection_rate,
        'false_positive_rate': false_positive_rate,
        'tp': tp,
        'fp': fp,
        'tn': tn,
        'fn': fn
    }

if __name__ == "__main__":
    results = run_attack_detection_test()
