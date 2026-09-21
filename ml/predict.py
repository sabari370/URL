"""
PhishGuard AI - ML Prediction Engine
Loads the persisted trained Random Forest model and performs inference.
Returns probabilistic prediction, risk score, and feature vector.
"""
import json
import os
import sys
import threading
from typing import Any, Dict, List, Optional
import numpy as np

# Ensure project root in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.feature_extraction import extract_features, features_to_vector
from utils.logger import setup_logger

logger = setup_logger("phishguard.predict", os.path.join(PROJECT_ROOT, "logs", "phishguard.log"))

_model = None
_scaler = None
_metadata = None
_lock = threading.Lock()


def _load_model():
    """
    Thread-safe lazy loading of model, scaler, and metadata.
    """
    global _model, _scaler, _metadata
    with _lock:
        if _model is not None and _scaler is not None:
            return

        model_path = os.path.join(PROJECT_ROOT, "models", "phishing_model.pkl")
        scaler_path = os.path.join(PROJECT_ROOT, "models", "feature_scaler.pkl")
        meta_path = os.path.join(PROJECT_ROOT, "models", "model_metadata.json")

        if not (os.path.isfile(model_path) and os.path.isfile(scaler_path)):
            logger.warning("Model or Scaler artifact not found on disk.")
            return

        try:
            import joblib
            _model = joblib.load(model_path)
            _scaler = joblib.load(scaler_path)
            logger.info("Successfully loaded ML model and scaler into memory.")
        except Exception as e:
            logger.error(f"Failed to load model/scaler artifacts: {e}")
            _model = None
            _scaler = None

        if os.path.isfile(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    _metadata = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load model metadata: {e}")
                _metadata = None


def is_model_available() -> bool:
    """
    Checks whether the ML model is trained and available for inference.
    """
    model_path = os.path.join(PROJECT_ROOT, "models", "phishing_model.pkl")
    scaler_path = os.path.join(PROJECT_ROOT, "models", "feature_scaler.pkl")
    return os.path.isfile(model_path) and os.path.isfile(scaler_path)


def get_model_info() -> Dict[str, Any]:
    """
    Returns stored model metadata or fallback information.
    """
    global _metadata
    if _metadata is None:
        _load_model()
    if _metadata:
        return _metadata

    meta_path = os.path.join(PROJECT_ROOT, "models", "model_metadata.json")
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def predict_url(url: str, thresholds: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    """
    Performs inference for a given URL using the trained model.

    Args:
        url: Normalized URL string.
        thresholds: Optional risk threshold dictionary (e.g. {'low': 30, 'suspicious': 60}).

    Returns:
        Dictionary containing classification, risk_score, probability, features, and model_available status.
    """
    if thresholds is None:
        thresholds = {"low": 30, "suspicious": 60}

    # Extract features safely
    features = extract_features(url)

    if not is_model_available():
        return {
            "success": False,
            "model_available": False,
            "classification": "Unknown",
            "risk_score": 0,
            "probability": 0.0,
            "features": features,
            "message": "ML model is not available. Please train the model using: python ml/train_model.py"
        }

    _load_model()
    if _model is None or _scaler is None:
        return {
            "success": False,
            "model_available": False,
            "classification": "Unknown",
            "risk_score": 0,
            "probability": 0.0,
            "features": features,
            "message": "Model artifacts could not be loaded into memory."
        }

    # Determine feature ordering from metadata
    meta = get_model_info()
    feature_names = meta.get("feature_names", list(features.keys()))

    # Convert to vector matching trained feature order
    feature_vector = features_to_vector(features, feature_names)
    X = np.array([feature_vector], dtype=np.float32)

    try:
        X_scaled = _scaler.transform(X)
        # Class 1 is phishing probability
        proba_array = _model.predict_proba(X_scaled)[0]
        # Classes might be [0, 1]
        classes = list(_model.classes_)
        if 1 in classes:
            phishing_idx = classes.index(1)
            phishing_prob = float(proba_array[phishing_idx])
        else:
            phishing_prob = float(proba_array[0])

        # Risk score on scale 0 to 100
        risk_score = int(round(phishing_prob * 100))

        # Classification based on configured thresholds
        low_thresh = thresholds.get("low", 30)
        suspicious_thresh = thresholds.get("suspicious", 60)

        if risk_score < low_thresh:
            classification = "Likely Safe"
        elif risk_score < suspicious_thresh:
            classification = "Suspicious"
        else:
            classification = "Likely Phishing"

        return {
            "success": True,
            "model_available": True,
            "classification": classification,
            "risk_score": risk_score,
            "probability": round(phishing_prob, 4),
            "features": features,
            "message": "Analysis completed successfully."
        }
    except Exception as e:
        logger.error(f"Inference error for URL '{url}': {e}")
        return {
            "success": False,
            "model_available": True,
            "classification": "Error",
            "risk_score": 0,
            "probability": 0.0,
            "features": features,
            "message": f"Inference calculation failed: {str(e)}"
        }
