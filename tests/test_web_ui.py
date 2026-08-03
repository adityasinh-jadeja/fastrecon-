"""
Tests for fastrecon.web_ui — API key authentication and SSRF protection
via Flask's test client.

Verifies that:
  - All /api/* routes return 401 without a valid API key.
  - Valid API keys (header and query param) are accepted.
  - SSRF targets are rejected with 400.
  - Page routes (/, /results) remain accessible without auth.
"""

import os
import pytest
from unittest.mock import patch

# Set a known API key before importing web_ui (it reads env at import time)
os.environ["FASTRECON_API_KEY"] = "test-api-key-12345"

from fastrecon.web_ui import app


@pytest.fixture
def client():
    """Create a Flask test client."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


API_KEY = "test-api-key-12345"
AUTH_HEADER = {"X-API-Key": API_KEY}


# ──────────────────────────────────────────────
#  Page Routes (no auth required)
# ──────────────────────────────────────────────

class TestPageRoutes:
    def test_homepage_accessible(self, client):
        response = client.get("/")
        assert response.status_code == 200

    def test_results_page_accessible(self, client):
        response = client.get("/results/test_scan_123")
        assert response.status_code == 200


# ──────────────────────────────────────────────
#  Authentication
# ──────────────────────────────────────────────

class TestAuthentication:
    def test_scan_requires_api_key(self, client):
        response = client.post("/api/scan", json={"target": "example.com"})
        assert response.status_code == 401
        assert response.json["error"] == "Unauthorized"

    def test_scan_with_valid_header_key(self, client):
        """Valid API key should not return 401 (may return 400/409/etc)."""
        response = client.post(
            "/api/scan",
            json={"target": "example.com"},
            headers=AUTH_HEADER,
        )
        assert response.status_code != 401

    def test_scan_with_invalid_key(self, client):
        response = client.post(
            "/api/scan",
            json={"target": "example.com"},
            headers={"X-API-Key": "wrong-key"},
        )
        assert response.status_code == 401

    def test_api_key_via_query_param(self, client):
        """API key can be passed as a query parameter."""
        response = client.get(f"/api/history?api_key={API_KEY}")
        assert response.status_code != 401

    def test_history_requires_auth(self, client):
        response = client.get("/api/history")
        assert response.status_code == 401

    def test_stats_requires_auth(self, client):
        response = client.get("/api/stats")
        assert response.status_code == 401

    def test_targets_get_requires_auth(self, client):
        response = client.get("/api/targets")
        assert response.status_code == 401

    def test_targets_post_requires_auth(self, client):
        response = client.post("/api/targets", json={"domain": "test.com"})
        assert response.status_code == 401

    def test_export_requires_auth(self, client):
        response = client.get("/api/export/test/csv")
        assert response.status_code == 401


# ──────────────────────────────────────────────
#  SSRF Protection via Web API
# ──────────────────────────────────────────────

class TestSSRFProtection:
    @patch("fastrecon.web_ui.is_safe_target", return_value=False)
    def test_unsafe_target_rejected(self, mock_validate, client):
        # Clear any in-progress scan from previous tests
        from fastrecon.web_ui import scan_store
        scan_store["current_scan"] = None

        response = client.post(
            "/api/scan",
            json={"target": "localhost"},
            headers=AUTH_HEADER,
        )
        assert response.status_code == 400
        assert "disallowed" in response.json["error"].lower() or "invalid" in response.json["error"].lower()

    def test_empty_target_rejected(self, client):
        response = client.post(
            "/api/scan",
            json={"target": ""},
            headers=AUTH_HEADER,
        )
        assert response.status_code == 400
