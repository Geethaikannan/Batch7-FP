import pickle
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from src.preprocessing import preprocess_data
from src.data_loader import load_data

BASE_DIR = '.'

train_path = f"{BASE_DIR}/data/UNSW_NB15_training-set.csv"
test_path = f"{BASE_DIR}/data/UNSW_NB15_testing-set.csv"

print("Loading data...")
train_df, test_df = load_data(train_path, test_path)

print("Fitting preprocessors...")
_, encoders = preprocess_data(train_df)  # This fits encoders in module state? Wait, need to extract.

# Manual fit for pickle
df = pd.concat([train_df, test_df])
X_temp, y_temp = preprocess_data(df)

scaler = StandardScaler()
scaler.fit(X_temp)

label_encoders = {}
categorical_cols = df.select_dtypes(include=['object']).columns.drop('label', errors='ignore')
for col in categorical_cols:
    le = LabelEncoder()
    le.fit(df[col].astype(str))
    label_encoders[col] = le

preprocessors = {
    'scaler': scaler,
    'label_encoders': label_encoders,
    'feature_names': X_temp.shape[1]
}

pickle.dump(preprocessors, open('models/preprocessors.pkl', 'wb'))
print("Saved models/preprocessors.pkl")

