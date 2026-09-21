"""
PhishGuard AI - URL Analyzer Orchestrator Service
Coordinates input validation, lexical feature extraction, ML classification,
explainability factors, and defensive recommendations.

SECURITY MANDATE:
This service and its dependents NEVER make network socket connections,
HTTP requests, or DNS resolutions against user-submitted URLs.
"""
import logging
from typing import Any, Dict
from ml.predict import is_model_available, predict_url
from services.risk_engine import analyze_risk_factors, get_recommendation, get_risk_summary
from utils.validators import validate_url

logger = logging.getLogger("phishguard.analyzer")


def analyze_url(raw_url: str, thresholds: Dict[str, int] = None) -> Dict[str, Any]:
    """
    Complete analysis pipeline for a user-submitted URL.

    Args:
        raw_url: The raw string submitted by the user.
        thresholds: Optional risk threshold dictionary.

    Returns:
        Structured result dict containing:
        - success (bool)
        - url (normalized)
        - classification
        - risk_score (0-100)
        - probability (0.0-1.0)
        - features (dict)
        - risk_factors (list)
        - risk_summary (dict)
        - recommendation (str)
        - model_available (bool)
        - disclaimer (str)
    """
    disclaimer = (
        "Automated probabilistic risk assessment. "
        "Predictions are calculated based on URL lexical and structural properties. "
        "Results do not guarantee complete safety or definitive maliciousness."
    )

    # 1. Validation and Normalization
    is_valid, err_msg, normalized_url = validate_url(raw_url)
    if not is_valid:
        return {
            "success": False,
            "error": err_msg,
            "url": raw_url,
            "model_available": is_model_available(),
            "disclaimer": disclaimer
        }

    # 2. Check Model Status
    if not is_model_available():
        return {
            "success": False,
            "error": "The Machine Learning model has not been trained yet. Please train the model using: python ml/train_model.py",
            "url": normalized_url,
            "model_available": False,
            "disclaimer": disclaimer
        }

    # 3. Machine Learning Inference
    pred_res = predict_url(normalized_url, thresholds=thresholds)
    if not pred_res.get("success", False):
        return {
            "success": False,
            "error": pred_res.get("message", "Prediction engine encountered an internal error."),
            "url": normalized_url,
            "model_available": pred_res.get("model_available", False),
            "disclaimer": disclaimer
        }

    features = pred_res.get("features", {})
    risk_score = pred_res.get("risk_score", 0)
    classification = pred_res.get("classification", "Unknown")
    probability = pred_res.get("probability", 0.0)

    # 4. Explainability & Risk Factor Breakdown
    risk_factors = analyze_risk_factors(features, risk_score)
    risk_summary = get_risk_summary(risk_factors)
    recommendation = get_recommendation(classification)

    logger.info(f"Analyzed '{normalized_url}': {classification} (Risk: {risk_score}/100)")

    return {
        "success": True,
        "url": normalized_url,
        "classification": classification,
        "risk_score": risk_score,
        "probability": probability,
        "features": features,
        "risk_factors": risk_factors,
        "risk_summary": risk_summary,
        "recommendation": recommendation,
        "model_available": True,
        "disclaimer": disclaimer
    }
