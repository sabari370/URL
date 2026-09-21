"""
PhishGuard AI - Model Training Pipeline
Loads dataset, extracts lexical features, trains a Random Forest Classifier,
evaluates performance metrics, and saves the trained model and metadata.

Usage:
    python ml/train_model.py [--dataset dataset/sample_dataset.csv]
"""
import argparse
import json
import os
import sys
from datetime import datetime
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.feature_extraction import extract_features, features_to_vector, get_feature_names
from utils.logger import setup_logger

logger = setup_logger("phishguard.train", os.path.join(PROJECT_ROOT, "logs", "phishguard.log"))


def train_pipeline(dataset_path: str, output_dir: str = None) -> dict:
    """
    Executes the full machine learning training pipeline.
    """
    if output_dir is None:
        output_dir = os.path.join(PROJECT_ROOT, "models")
    os.makedirs(output_dir, exist_ok=True)

    if not os.path.isfile(dataset_path):
        raise FileNotFoundError(f"Dataset file not found at: {dataset_path}")

    logger.info(f"Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)

    # Validate dataset structure
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset must contain 'url' and 'label' columns.")

    # Clean dataset
    initial_count = len(df)
    df = df.dropna(subset=["url", "label"])
    df["label"] = df["label"].astype(int)
    df = df[df["label"].isin([0, 1])]
    df = df.drop_duplicates(subset=["url"])
    logger.info(f"Cleaned dataset: {len(df)} rows retained from {initial_count} initial entries.")

    feature_names = get_feature_names()
    logger.info(f"Extracting {len(feature_names)} features for {len(df)} URLs...")

    # Extract features for all URLs
    X_rows = []
    y = df["label"].values

    for url in df["url"]:
        feats = extract_features(str(url))
        vec = features_to_vector(feats, feature_names)
        X_rows.append(vec)

    X = np.array(X_rows, dtype=np.float32)

    # Stratified Train-Test Split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    logger.info(f"Train samples: {len(y_train)} (Benign: {sum(y_train==0)}, Phishing: {sum(y_train==1)})")
    logger.info(f"Test samples: {len(y_test)} (Benign: {sum(y_test==0)}, Phishing: {sum(y_test==1)})")

    # Feature Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train Random Forest Classifier
    logger.info("Training Random Forest Classifier (n_estimators=100)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1
    )
    clf.fit(X_train_scaled, y_train)

    # Evaluate on test set
    y_pred = clf.predict(X_test_scaled)
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()

    report_str = classification_report(y_test, y_pred, target_names=["Benign (0)", "Phishing (1)"])
    logger.info(f"\nModel Evaluation Report:\n{report_str}")
    logger.info(f"Confusion Matrix: {cm}")

    # Save artifacts
    model_file = os.path.join(output_dir, "phishing_model.pkl")
    scaler_file = os.path.join(output_dir, "feature_scaler.pkl")
    meta_file = os.path.join(output_dir, "model_metadata.json")

    joblib.dump(clf, model_file)
    joblib.dump(scaler, scaler_file)

    metadata = {
        "model_name": "Random Forest Classifier",
        "version": "1.0.0",
        "training_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "dataset_file": os.path.basename(dataset_path),
        "total_samples": len(df),
        "train_samples": len(y_train),
        "test_samples": len(y_test),
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": cm
        }
    }

    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)

    logger.info(f"Model saved to {model_file}")
    logger.info(f"Scaler saved to {scaler_file}")
    logger.info(f"Metadata saved to {meta_file}")

    print("\n" + "="*50)
    print("PHISHGUARD AI - TRAINING COMPLETED SUCCESSFULLY")
    print("="*50)
    print(f"Accuracy : {acc * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"Recall   : {rec * 100:.2f}%")
    print(f"F1-Score : {f1 * 100:.2f}%")
    print(f"Confusion Matrix (TN, FP / FN, TP): {cm}")
    print("="*50)

    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train PhishGuard AI Random Forest Model")
    parser.add_argument(
        "--dataset",
        type=str,
        default=os.path.join(PROJECT_ROOT, "dataset", "sample_dataset.csv"),
        help="Path to training dataset CSV file"
    )
    args = parser.parse_args()
    train_pipeline(args.dataset)
