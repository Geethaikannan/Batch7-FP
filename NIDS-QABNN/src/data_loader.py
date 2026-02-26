import pandas as pd

def load_data(train_path, test_path):
    """
    Load UNSW-NB15 training and testing datasets.
    """
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    return train_df, test_df
