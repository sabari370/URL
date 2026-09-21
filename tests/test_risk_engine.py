"""
PhishGuard AI - Tests for Risk Engine and Explainability
Verifies factor classification, recommendation strings, and threshold mapping.
"""
import os
import sys
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from services.risk_engine import analyze_risk_factors, get_recommendation, get_risk_summary


class TestRiskEngine:
    """Test suite for explainability factor calculations."""

    def test_factor_structure(self):
        sample_features = {
            "url_length": 85,
            "suspicious_keyword_count": 2,
            "subdomain_count": 3,
            "has_ip_host": 1,
            "has_https": 0,
            "special_char_count": 5,
            "at_symbol_count": 1,
            "is_url_shortener": 1,
            "has_suspicious_tld": 1,
            "has_suspicious_port": 1,
            "port": 8080,
            "has_punycode": 1
        }
        factors = analyze_risk_factors(sample_features, 85)
        assert isinstance(factors, list)
        assert len(factors) > 0

        for f in factors:
            assert "factor" in f
            assert "value" in f
            assert "level" in f
            assert "risk_contribution" in f
            assert "description" in f
            assert f["level"] in ["HIGH", "MEDIUM", "LOW"]

    def test_https_disclaimer_present(self):
        sample_features = {"has_https": 1}
        factors = analyze_risk_factors(sample_features, 10)
        https_factor = next((f for f in factors if "HTTPS" in f["factor"]), None)
        assert https_factor is not None
        # Must responsibly note that HTTPS doesn't guarantee legitimacy
        assert "not guarantee" in https_factor["description"].lower()

    def test_risk_summary_counts(self):
        factors = [
            {"level": "HIGH"},
            {"level": "HIGH"},
            {"level": "MEDIUM"},
            {"level": "LOW"}
        ]
        summary = get_risk_summary(factors)
        assert summary["high"] == 2
        assert summary["medium"] == 1
        assert summary["low"] == 1

    def test_recommendation_copy(self):
        rec_phish = get_recommendation("Likely Phishing")
        rec_susp = get_recommendation("Suspicious")
        rec_safe = get_recommendation("Likely Safe")

        assert "critical" in rec_phish.lower() or "warning" in rec_phish.lower()
        assert "caution" in rec_susp.lower() or "verify" in rec_susp.lower()
        assert "safe" in rec_safe.lower() or "vigilant" in rec_safe.lower()
