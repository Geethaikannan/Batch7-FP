import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler

def preprocess_data(df):
    df = df.copy()

    # Remove ID column if exists
    if 'id' in df.columns:
        df.drop(columns=['id'], inplace=True)

    # Separate label
    y = df['label']
    X = df.drop(columns=['label'])

    # Encode categorical columns
    for col in X.select_dtypes(include=['object']).columns:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col])

    # Scale features
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    return X, y
