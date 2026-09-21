"""
PhishGuard AI - Tests for REST API Endpoints
Uses Flask test client to verify /api/health, /api/analyze, and /api/history.
"""
import os
import sys
import json
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import create_app


@pytest.fixture
def client():
    """Creates a configured Flask test client."""
    os.environ["FLASK_ENV"] = "development"
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestAPIEndpoints:
    """Test suite for REST API routes."""

    def test_health_check(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.get_json()
        assert "status" in data
        assert "database" in data
        assert "model" in data

    def test_analyze_valid_url(self, client):
        payload = {"url": "https://www.google.com"}
        response = client.post(
            "/api/analyze",
            data=json.dumps(payload),
            content_type="application/json"
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "classification" in data
        assert "risk_score" in data
        assert "probability" in data
        assert "risk_factors" in data

    def test_analyze_missing_url(self, client):
        payload = {}
        response = client.post(
            "/api/analyze",
            data=json.dumps(payload),
            content_type="application/json"
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False

    def test_analyze_non_json_request(self, client):
        response = client.post(
            "/api/analyze",
            data="url=https://example.com",
            content_type="application/x-www-form-urlencoded"
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False

    def test_api_history_unauthorized_without_session(self, client):
        response = client.get("/api/history")
        assert response.status_code == 401
        data = response.get_json()
        assert data["success"] is False
