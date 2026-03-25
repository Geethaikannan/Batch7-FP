import pickle
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from src.preprocessing import preprocess_data
from src.data_loader import load_data
import os

os.makedirs('models', exist_ok=True)

train_path = 'data/UNSW_NB15_training-set.csv'
test_path = 'data/UNSW_NB15_testing-set.csv'

print("Loading data...")
train_df, test_df = load_data(train_path, test_path)

print("Fitting preprocessors...")
X_temp, y_temp = preprocess_data(pd.concat([train_df, test_df]))

scaler = StandardScaler()
scaler.fit(X_temp)

label_encoders = {}
df = pd.concat([train_df, test_df])
categorical_cols = df.select_dtypes(include=['object']).columns.drop('label', errors='ignore')
for col in categorical_cols:
    le = LabelEncoder()
    le.fit(df[col].astype(str))
    label_encoders[col] = le

preprocessors = {
    'scaler': scaler,
    'label_encoders': label_encoders,
    'n_features': X_temp.shape[1]
}

pickle.dump(preprocessors, open('models/preprocessors.pkl', 'wb'))
print("Saved models/preprocessors.pkl")
print(f"Features: {preprocessors['n_features']}")

