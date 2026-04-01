import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler

def preprocess_data(df, encoders=None, scaler=None, fit=False):
    """Preprocess data with optional encoders and scaler
    
    Args:
        df: DataFrame to preprocess
        encoders: Dict of LabelEncoders for categorical columns (for transform)
        scaler: StandardScaler for feature scaling (for transform)
        fit: If True, fit new encoders/scaler. If False, use provided ones.
    
    Returns:
        X: Preprocessed features
        y: Labels (if present)
        encoders: Dict of fitted LabelEncoders (if fit=True)
        scaler: Fitted StandardScaler (if fit=True)
    """
    df = df.copy()

    # Remove ID column if exists
    if 'id' in df.columns:
        df.drop(columns=['id'], inplace=True)

    # Separate label
    has_label = 'label' in df.columns
    if has_label:
        y = df['label'].values
        X = df.drop(columns=['label'])
    else:
        y = None
        X = df

    # Store column names for later
    feature_columns = X.columns.tolist()
    categorical_cols = X.select_dtypes(include=['object']).columns.tolist()
    
    if fit:
        # Train mode: create new encoders
        encoders_dict = {}
        for col in categorical_cols:
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col])
            encoders_dict[col] = le
        
        # Scale features
        scaler_new = StandardScaler()
        X = scaler_new.fit_transform(X)
        
        return X, y, encoders_dict, scaler_new
    else:
        # Test/inference mode: use provided encoders
        if encoders is not None:
            for col in categorical_cols:
                if col in encoders:
                    try:
                        X[col] = encoders[col].transform(X[col])
                    except ValueError:
                        # Handle unknown categories by mapping to 0
                        known_classes = set(encoders[col].classes_)
                        X[col] = X[col].apply(lambda x: encoders[col].transform([x])[0] if x in known_classes else 0)
        
        # Scale with provided scaler
        if scaler is not None:
            X = scaler.transform(X)
        
        return X, y
