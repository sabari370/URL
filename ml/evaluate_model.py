"""
PhishGuard AI - Model Evaluation Script
Loads the persisted trained model, scaler, and metadata to evaluate performance
on a test or evaluation dataset.

Usage:
    python ml/evaluate_model.py [--dataset dataset/sample_dataset.csv]
"""
import argparse
import json
import os
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score

# Ensure project root in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.feature_extraction import extract_features, features_to_vector


def evaluate(dataset_path: str):
    models_dir = os.path.join(PROJECT_ROOT, "models")
    model_file = os.path.join(models_dir, "phishing_model.pkl")
    scaler_file = os.path.join(models_dir, "feature_scaler.pkl")
    meta_file = os.path.join(models_dir, "model_metadata.json")

    if not os.path.isfile(model_file) or not os.path.isfile(scaler_file):
        print("\n[!] ERROR: ML model is not available.")
        print("Please train the model first using: python ml/train_model.py\n")
        return

    print(f"[*] Loading model from: {model_file}")
    model = joblib.load(model_file)
    scaler = joblib.load(scaler_file)

    feature_names = []
    if os.path.isfile(meta_file):
        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)
            feature_names = meta.get("feature_names", [])

    print(f"[*] Loading evaluation dataset: {dataset_path}")
    df = pd.read_csv(dataset_path).dropna(subset=["url", "label"])
    df["label"] = df["label"].astype(int)

    X_rows = []
    for url in df["url"]:
        feats = extract_features(str(url))
        vec = features_to_vector(feats, feature_names)
        X_rows.append(vec)

    X = np.array(X_rows, dtype=np.float32)
    y_true = df["label"].values

    X_scaled = scaler.transform(X)
    y_pred = model.predict(X_scaled)
    y_proba = model.predict_proba(X_scaled)[:, 1]

    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)

    print("\n" + "="*55)
    print("PHISHGUARD AI - MODEL PERFORMANCE EVALUATION REPORT")
    print("="*55)
    print(f"Total Evaluation Samples: {len(y_true)}")
    print(f"Accuracy               : {acc * 100:.2f}%")
    print(f"Precision              : {prec * 100:.2f}%")
    print(f"Recall                 : {rec * 100:.2f}%")
    print(f"F1-Score               : {f1 * 100:.2f}%")
    print("\nConfusion Matrix:")
    print("                 Predicted Benign   Predicted Phishing")
    print(f"Actual Benign           {cm[0][0]:<15}    {cm[0][1]}")
    print(f"Actual Phishing         {cm[1][0]:<15}    {cm[1][1]}")
    print("\nDetailed Classification Breakdown:")
    print(classification_report(y_true, y_pred, target_names=["Benign", "Phishing"]))
    print("="*55)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate PhishGuard AI ML Model")
    parser.add_argument(
        "--dataset",
        type=str,
        default=os.path.join(PROJECT_ROOT, "dataset", "sample_dataset.csv"),
        help="Path to evaluation dataset CSV file"
    )
    args = parser.parse_args()
    evaluate(args.dataset)
