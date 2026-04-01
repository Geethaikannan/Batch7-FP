import os
import numpy as np
import pickle
import matplotlib.pyplot as plt

from sklearn.metrics import (
    confusion_matrix,
    accuracy_score,
    roc_curve,
    auc
)
from sklearn.ensemble import RandomForestClassifier

from src.data_loader import load_data
from src.preprocessing import preprocess_data
from src.qabnn import QABNN
from src.evaluation import evaluate_model


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TRAIN_PATH = os.path.join(BASE_DIR, "data", "UNSW_NB15_training-set.csv")
TEST_PATH = os.path.join(BASE_DIR, "data", "UNSW_NB15_testing-set.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "qabnn_model.pkl")
PREPROCESSORS_PATH = os.path.join(MODEL_DIR, "preprocessors.pkl")


def main():
    print("Loading dataset...")
    train_df, test_df = load_data(TRAIN_PATH, TEST_PATH)

    print("Preprocessing...")
    X_train, y_train, encoders, scaler = preprocess_data(train_df, fit=True)
    X_test, y_test = preprocess_data(test_df, encoders=encoders, scaler=scaler, fit=False)

    y_train = np.array(y_train)
    y_test = np.array(y_test)

    # ==========================
    # QABNN
    # ==========================
    print("\nTraining QABNN...")
    qabnn = QABNN()
    qabnn.fit(X_train, y_train)

    y_pred_qabnn = qabnn.predict(X_test)
    qabnn_probs = qabnn.predict_proba(X_test)[:, 1]

    # ==========================
    # Random Forest
    # ==========================
    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100)
    rf.fit(X_train, y_train)

    y_pred_rf = rf.predict(X_test)
    rf_probs = rf.predict_proba(X_test)[:, 1]

    # ==========================
    # Accuracy
    # ==========================
    print("\n=== Accuracy ===")
    print("QABNN:", accuracy_score(y_test, y_pred_qabnn))
    print("RF:", accuracy_score(y_test, y_pred_rf))

    # ==========================
    # Confusion Matrix
    # ==========================
    print("\n=== QABNN Confusion Matrix ===")
    print(confusion_matrix(y_test, y_pred_qabnn))

    print("\n=== RF Confusion Matrix ===")
    print(confusion_matrix(y_test, y_pred_rf))

    # ==========================
    # ROC Curve
    # ==========================
    fpr_q, tpr_q, _ = roc_curve(y_test, qabnn_probs)
    fpr_rf, tpr_rf, _ = roc_curve(y_test, rf_probs)

    auc_q = auc(fpr_q, tpr_q)
    auc_rf = auc(fpr_rf, tpr_rf)

    plt.figure()
    plt.plot(fpr_q, tpr_q, label=f"QABNN (AUC = {auc_q:.4f})")
    plt.plot(fpr_rf, tpr_rf, label=f"RF (AUC = {auc_rf:.4f})")
    plt.plot([0, 1], [0, 1], linestyle="--")

    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve Comparison")
    plt.legend()
    plt.show()

    # ==========================
    # Detailed Metrics
    # ==========================
    q_metrics = evaluate_model(y_test, y_pred_qabnn)
    rf_metrics = evaluate_model(y_test, y_pred_rf)

    print("\n=== QABNN Metrics ===")
    for k, v in q_metrics.items():
        print(k, v)

    print("\n=== RF Metrics ===")
    for k, v in rf_metrics.items():
        print(k, v)

    # ==========================
    # Save Models
    # ==========================
    print(f"\nSaving QABNN model to {MODEL_PATH}...")
    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(qabnn, f)
    print(f"[OK] Model saved successfully")
    
    print(f"Saving preprocessors to {PREPROCESSORS_PATH}...")
    with open(PREPROCESSORS_PATH, 'wb') as f:
        pickle.dump({'encoders': encoders, 'scaler': scaler}, f)
    print(f"[OK] Preprocessors saved successfully")


if __name__ == "__main__":
    main()
