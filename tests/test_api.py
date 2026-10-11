"""
tests/test_api.py — Integration tests for Flask API endpoints.
Run with: pytest tests/ -v
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

import pytest
import json


@pytest.fixture(scope="module")
def client():
    """Create a Flask test client backed by an in-memory SQLite DB."""
    import os
    os.environ.setdefault("SECRET_KEY",       "test-secret")
    os.environ.setdefault("JWT_SECRET_KEY",   "test-jwt-secret")
    os.environ.setdefault("DATABASE_URL",     "sqlite:///:memory:")
    os.environ.setdefault("FLASK_DEBUG",      "0")
    os.environ["RATE_LIMIT_SCAN"] = "1000 per minute"
    os.environ["RATE_LIMIT_AUTH"] = "1000 per minute"

    from server import create_app
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ── Health check ──────────────────────────────────────────────────────────

def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] == "ok"


# ── 404 handler ───────────────────────────────────────────────────────────

def test_404(client):
    r = client.get("/api/nonexistent")
    assert r.status_code == 404
    assert "error" in r.get_json()


# ── Auth: register ────────────────────────────────────────────────────────

def test_register_success(client):
    r = client.post("/api/auth/register", json={
        "username": "testuser",
        "email":    "test@example.com",
        "password": "SecurePass123!"
    })
    assert r.status_code == 201
    data = r.get_json()
    assert "token" in data
    assert data["user"]["username"] == "testuser"


def test_register_duplicate_username(client):
    client.post("/api/auth/register", json={
        "username": "dupuser", "email": "dup1@x.com", "password": "password123"
    })
    r = client.post("/api/auth/register", json={
        "username": "dupuser", "email": "dup2@x.com", "password": "password123"
    })
    assert r.status_code == 409


def test_register_weak_password(client):
    r = client.post("/api/auth/register", json={
        "username": "weakuser", "email": "weak@x.com", "password": "123"
    })
    assert r.status_code == 400


def test_register_invalid_email(client):
    r = client.post("/api/auth/register", json={
        "username": "bademail", "email": "not-an-email", "password": "SecurePass123"
    })
    assert r.status_code == 400


# ── Auth: login ───────────────────────────────────────────────────────────

def test_login_success(client):
    client.post("/api/auth/register", json={
        "username": "loginuser", "email": "login@x.com", "password": "MyPassword99"
    })
    r = client.post("/api/auth/login", json={
        "username": "loginuser", "password": "MyPassword99"
    })
    assert r.status_code == 200
    assert "token" in r.get_json()


def test_login_wrong_password(client):
    r = client.post("/api/auth/login", json={
        "username": "loginuser", "password": "wrongpassword"
    })
    assert r.status_code == 401


def test_login_nonexistent_user(client):
    r = client.post("/api/auth/login", json={
        "username": "ghost", "password": "anything"
    })
    assert r.status_code == 401


# ── Auth: /me ─────────────────────────────────────────────────────────────

def test_me_authenticated(client):
    r_reg = client.post("/api/auth/register", json={
        "username": "meuser", "email": "me@x.com", "password": "SecurePass123"
    })
    token = r_reg.get_json()["token"]
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.get_json()["user"]["username"] == "meuser"


def test_me_unauthenticated(client):
    r = client.get("/api/auth/me")
    assert r.status_code == 401


def test_me_invalid_token(client):
    r = client.get("/api/auth/me", headers={"Authorization": "Bearer not.a.real.token"})
    assert r.status_code == 401


# ── Scan: URL ─────────────────────────────────────────────────────────────

def test_scan_url_valid(client):
    r = client.post("/api/scan/url", json={"url": "https://google.com"})
    assert r.status_code == 200
    data = r.get_json()
    assert "risk_score" in data
    assert "verdict" in data
    assert data["verdict"] in ("safe", "suspicious", "phishing")
    assert 0.0 <= data["risk_score"] <= 1.0


def test_scan_url_phishing_sample(client):
    r = client.post("/api/scan/url", json={"url": "http://paypal-secure-login.tk/verify-account"})
    assert r.status_code == 200
    data = r.get_json()
    # Should score above 0 due to heuristics
    assert data["risk_score"] > 0


def test_scan_url_missing_field(client):
    r = client.post("/api/scan/url", json={})
    assert r.status_code == 422


def test_scan_url_invalid_url(client):
    r = client.post("/api/scan/url", json={"url": "not-a-url"})
    assert r.status_code == 422


def test_scan_url_xss_input(client):
    r = client.post("/api/scan/url", json={"url": "<script>alert(1)</script>"})
    # Should be sanitized and rejected as invalid URL
    assert r.status_code == 422


# ── Scan: Email ───────────────────────────────────────────────────────────

def test_scan_email_valid(client):
    r = client.post("/api/scan/email", json={
        "email_text": "Your account has been suspended. Click here to verify."
    })
    assert r.status_code == 200
    data = r.get_json()
    assert "risk_score" in data
    assert data["verdict"] in ("safe", "suspicious", "phishing")


def test_scan_email_empty(client):
    r = client.post("/api/scan/email", json={"email_text": ""})
    assert r.status_code == 422


def test_scan_email_clean_text(client):
    r = client.post("/api/scan/email", json={
        "email_text": "Hi team, please review the attached quarterly report."
    })
    assert r.status_code == 200


# ── History (requires auth) ───────────────────────────────────────────────

def _get_token(client, username, email, password="Password123"):
    client.post("/api/auth/register", json={"username": username, "email": email, "password": password})
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    return r.get_json()["token"]


def test_history_unauthenticated(client):
    r = client.get("/api/history")
    assert r.status_code == 401


def test_history_empty_for_new_user(client):
    token = _get_token(client, "histuser", "hist@x.com")
    r = client.get("/api/history", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["total"] == 0
    assert data["items"] == []


def test_history_populated_after_scan(client):
    token = _get_token(client, "scanhistuser", "scanhist@x.com")
    # Do a scan with auth
    client.post("/api/scan/url",
        json={"url": "https://google.com"},
        headers={"Authorization": f"Bearer {token}"}
    )
    r = client.get("/api/history", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.get_json()["total"] >= 1


def test_history_stats(client):
    token = _get_token(client, "statsuser", "stats@x.com")
    client.post("/api/scan/url",
        json={"url": "https://github.com"},
        headers={"Authorization": f"Bearer {token}"}
    )
    r = client.get("/api/history/stats", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.get_json()
    assert "total" in data
    assert "stats" in data


def test_bulk_delete_history(client):
    """DELETE /api/history should remove all records for the user in one call."""
    token = _get_token(client, "bulkdeluser", "bulkdel@x.com")
    # Create two scan records
    for url in ["https://google.com", "https://github.com"]:
        client.post("/api/scan/url",
            json={"url": url},
            headers={"Authorization": f"Bearer {token}"}
        )
    # Confirm records exist
    r = client.get("/api/history", headers={"Authorization": f"Bearer {token}"})
    assert r.get_json()["total"] >= 2

    # Bulk delete
    r = client.delete("/api/history", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.get_json()
    assert "deleted" in data
    assert data["deleted"] >= 2

    # Confirm history is empty
    r = client.get("/api/history", headers={"Authorization": f"Bearer {token}"})
    assert r.get_json()["total"] == 0


def test_bulk_delete_unauthenticated(client):
    r = client.delete("/api/history")
    assert r.status_code == 401


# ── PhishGuard 2.0 Forensics & Everyday Defense Tests ───────────────────────

def test_scan_url_missing_tld_gjgku(client):
    """https://gjgku has no TLD and abnormal consonants — must be flagged as phishing."""
    r = client.post("/api/scan/url", json={"url": "https://gjgku"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["verdict"] == "phishing"
    assert data["risk_score"] >= 0.70
    assert any("Missing or Invalid TLD" in f["title"] for f in data["explainable_factors"])


def test_scan_url_safe_google(client):
    r = client.post("/api/scan/url", json={"url": "https://google.com"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["verdict"] == "safe"
    assert data["risk_score"] < 0.35


def test_scan_message_electricity_scam(client):
    msg = "Your electricity power supply will be disconnected tonight at 9:30 PM due to unpaid bill. Call officer immediately."
    r = client.post("/api/scan/message", json={"message_text": msg})
    assert r.status_code == 200
    data = r.get_json()
    assert data["verdict"] in ("phishing", "suspicious")
    assert "Electricity" in data["scam_category"]
    assert "emergency_helpline" in data


def test_scan_qr_upi_fraud_trap(client):
    payload = "upi://pay?pa=scammer@okhdfc&pn=Cashback%20Reward&am=5000&tn=Electricity%20Refund"
    r = client.post("/api/scan/qr", json={"payload": payload})
    assert r.status_code == 200
    data = r.get_json()
    assert data["verdict"] == "CRITICAL RISK"
    assert data["upi_analysis"]["is_fraud_trap"] is True
    assert "WITHDRAW/PAY" in data["upi_analysis"]["warning_title"]


def test_scan_unshorten_endpoint(client):
    r = client.post("/api/scan/unshorten", json={"url": "https://google.com"})
    assert r.status_code == 200
    data = r.get_json()
    assert "original_url" in data
    assert "final_url" in data

