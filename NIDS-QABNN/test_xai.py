"""
Quick test to verify XAI functionality
"""
import os
import sys
import numpy as np
import pickle
import pandas as pd

# Add project to path
sys.path.insert(0, os.path.dirname(__file__))

from src.qabnn import QABNN
from src.xai_explainer import QABNNExplainer
from src.data_loader import load_data
from src.preprocessing import preprocess_data

print("Loading data...")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_PATH = os.path.join(BASE_DIR, "data", "UNSW_NB15_testing-set.csv")
train_path = os.path.join(BASE_DIR, "data", "UNSW_NB15_training-set.csv")

# Load test data
_, test_df = load_data(train_path, TEST_PATH)
X_test, y_test = preprocess_data(test_df)

print(f"Test data shape: {X_test.shape}")
print(f"Test DF shape: {test_df.shape}")
print(f"Columns: {test_df.columns.tolist()}")

# Load preprocessors
print("Loading preprocessors...")
with open(os.path.join(BASE_DIR, "models", "preprocessors.pkl"), 'rb') as f:
    preprocessors = pickle.load(f)

# Train model
print("Training QABNN...")
train_df, _ = load_data(train_path, TEST_PATH)
X_train, y_train = preprocess_data(train_df)
model = QABNN()
model.fit(X_train, y_train)

# Initialize explainer
print("Initializing explainer...")
feature_names = [col for col in test_df.columns if col not in ['label', 'attack_cat']]
print(f"Found {len(feature_names)} features")
print(f"Feature names: {feature_names[:10]}...")  # Print first 10

explainer = QABNNExplainer(model, feature_names=feature_names)

# Test on a sample
print("\nTesting XAI on sample 0 (Normal traffic)...")
sample = X_test[0:1]
metadata = {
    'proto': str(test_df.iloc[0].get('proto', 'N/A')),
    'service': str(test_df.iloc[0].get('service', 'N/A')),
    'state': str(test_df.iloc[0].get('state', 'N/A')),
    'attack_cat': str(test_df.iloc[0].get('attack_cat', 'Normal')),
}

print(f"Sample shape: {sample.shape}")
print(f"Metadata: {metadata}")

try:
    explanation = explainer.explain_prediction(sample, metadata)
    print("\n✅ XAI Explanation generated successfully!")
    print(f"Prediction: {explanation['prediction']}")
    print(f"Confidence: {explanation['confidence_percentage']}%")
    print(f"Reasoning: {explanation['reasoning'][:100]}...")
    print(f"Top features: {[f['feature'] for f in explanation['top_discriminative_features'][:3]]}")
except Exception as e:
    print(f"❌ Error generating explanation: {e}")
    import traceback
    traceback.print_exc()

# Test on an attack sample if available
attack_samples = np.where(y_test == 1)[0]
if len(attack_samples) > 0:
    print("\nTesting XAI on first attack sample...")
    idx = attack_samples[0]
    sample = X_test[idx:idx+1]
    metadata = {
        'proto': str(test_df.iloc[idx].get('proto', 'N/A')),
        'service': str(test_df.iloc[idx].get('service', 'N/A')),
        'state': str(test_df.iloc[idx].get('state', 'N/A')),
        'attack_cat': str(test_df.iloc[idx].get('attack_cat', 'Generic')),
    }
    
    try:
        explanation = explainer.explain_prediction(sample, metadata)
        print("✅ XAI Explanation for attack generated successfully!")
        print(f"Prediction: {explanation['prediction']}")
        print(f"Confidence: {explanation['confidence_percentage']}%")
        print(f"Reasoning: {explanation['reasoning'][:100]}...")
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

print("\n✅ Test completed!")
