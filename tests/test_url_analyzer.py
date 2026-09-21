"""
PhishGuard AI - Tests for URL Validation & Feature Extraction
Verifies URL parsing, RFC compliance, and feature extraction vectors.
"""
import os
import sys
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.feature_extraction import extract_features, features_to_vector, get_feature_names
from utils.validators import allowed_file, is_private_address, validate_url


class TestURLValidation:
    """Test suite for URL validation and normalization."""

    def test_valid_https_url(self):
        valid, err, norm = validate_url("https://www.google.com/search?q=cybersecurity")
        assert valid is True
        assert err == ""
        assert norm.startswith("https://www.google.com")

    def test_valid_http_url(self):
        valid, err, norm = validate_url("http://example.com/docs")
        assert valid is True
        assert err == ""
        assert norm.startswith("http://example.com")

    def test_empty_url(self):
        valid, err, norm = validate_url("")
        assert valid is False
        assert "empty" in err.lower()
        assert norm is None

    def test_whitespace_only_url(self):
        valid, err, norm = validate_url("   ")
        assert valid is False
        assert "empty" in err.lower()

    def test_missing_scheme_auto_prepends_http(self):
        valid, err, norm = validate_url("example.com/login")
        assert valid is True
        assert norm.startswith("http://example.com")

    def test_unsupported_scheme_ftp(self):
        valid, err, norm = validate_url("ftp://files.example.com/archive.zip")
        assert valid is False
        assert "unsupported scheme" in err.lower()

    def test_unsupported_scheme_file(self):
        valid, err, norm = validate_url("file:///etc/passwd")
        assert valid is False
        assert "unsupported scheme" in err.lower()

    def test_url_length_exceeded(self):
        long_url = "https://example.com/" + "a" * 2100
        valid, err, norm = validate_url(long_url)
        assert valid is False
        assert "too long" in err.lower()

    def test_ip_based_url_accepted_for_analysis(self):
        valid, err, norm = validate_url("http://192.168.1.1/admin")
        assert valid is True
        assert norm == "http://192.168.1.1/admin"


class TestPrivateAddresses:
    """Test suite for private address detection."""

    def test_localhost(self):
        assert is_private_address("localhost") is True

    def test_127_loopback(self):
        assert is_private_address("127.0.0.1") is True

    def test_10_private_network(self):
        assert is_private_address("10.0.0.1") is True

    def test_public_domain(self):
        assert is_private_address("google.com") is False


class TestFileValidation:
    """Test suite for uploaded QR file validation."""

    def test_allowed_extensions(self):
        exts = {"png", "jpg", "jpeg"}
        assert allowed_file("test.png", exts) is True
        assert allowed_file("photo.JPG", exts) is True
        assert allowed_file("malware.exe", exts) is False
        assert allowed_file("noextension", exts) is False


class TestFeatureExtraction:
    """Test suite for numerical feature extraction logic."""

    def test_extract_features_keys(self):
        feats = extract_features("https://www.example.com/path?q=1")
        feature_names = get_feature_names()
        for name in feature_names:
            assert name in feats, f"Missing feature '{name}'"

    def test_https_flag(self):
        f_https = extract_features("https://www.example.com")
        f_http = extract_features("http://www.example.com")
        assert f_https["has_https"] == 1
        assert f_http["has_https"] == 0

    def test_ip_host_detection(self):
        f_ip = extract_features("http://192.168.1.100/login")
        f_domain = extract_features("http://example.com/login")
        assert f_ip["has_ip_host"] == 1
        assert f_domain["has_ip_host"] == 0

    def test_suspicious_keyword_counter(self):
        f = extract_features("http://example.com/login/verify/banking/account")
        assert f["suspicious_keyword_count"] >= 3

    def test_subdomain_depth_count(self):
        f = extract_features("http://a.b.c.example.com")
        assert f["subdomain_count"] >= 2

    def test_at_symbol_detection(self):
        f = extract_features("http://google.com@phishing-site.xyz/login")
        assert f["at_symbol_count"] == 1

    def test_shortener_detection(self):
        f_short = extract_features("https://bit.ly/3xSample")
        assert f_short["is_url_shortener"] == 1

    def test_punycode_detection(self):
        f_puny = extract_features("http://xn--g0gle-1qa.com/login")
        assert f_puny["has_punycode"] == 1

    def test_features_to_vector_ordering(self):
        names = get_feature_names()
        feats = extract_features("https://example.com")
        vec = features_to_vector(feats, names)
        assert len(vec) == len(names)
        assert all(isinstance(x, (int, float)) for x in vec)
