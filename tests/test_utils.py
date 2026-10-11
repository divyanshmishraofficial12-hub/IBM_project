"""
tests/test_utils.py — Unit tests for input sanitization and validation helpers.
Run with: pytest tests/ -v
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

import pytest
from utils import (
    sanitize_input,
    validate_url,
    validate_email_text,
    heuristic_url_score,
    heuristic_email_score,
    compute_verdict,
)


# ── sanitize_input ────────────────────────────────────────────────────────

class TestSanitizeInput:
    def test_strips_html_tags(self):
        result = sanitize_input("<script>alert('xss')</script>hello")
        assert "<script>" not in result
        assert "alert" in result or "hello" in result

    def test_truncates_to_max_length(self):
        long_str = "a" * 5000
        result = sanitize_input(long_str, max_length=100)
        assert len(result) <= 100

    def test_raises_on_non_string(self):
        with pytest.raises(ValueError):
            sanitize_input(12345)

    def test_strips_null_bytes(self):
        result = sanitize_input("hello\x00world")
        assert "\x00" not in result

    def test_normal_text_passes_through(self):
        text = "https://example.com/page?q=test"
        result = sanitize_input(text)
        assert "example.com" in result


# ── validate_url ──────────────────────────────────────────────────────────

class TestValidateUrl:
    def test_valid_https_url(self):
        ok, msg = validate_url("https://google.com")
        assert ok is True

    def test_valid_http_url(self):
        ok, msg = validate_url("http://example.com/path?q=1")
        assert ok is True

    def test_missing_scheme(self):
        ok, msg = validate_url("google.com")
        assert ok is False

    def test_ftp_rejected(self):
        ok, msg = validate_url("ftp://files.example.com")
        assert ok is False

    def test_empty_url(self):
        ok, msg = validate_url("")
        assert ok is False

    def test_url_too_long(self):
        ok, msg = validate_url("https://example.com/" + "a" * 2100)
        assert ok is False

    def test_missing_domain(self):
        ok, msg = validate_url("https://")
        assert ok is False


# ── validate_email_text ───────────────────────────────────────────────────

class TestValidateEmailText:
    def test_valid_text(self):
        ok, _ = validate_email_text("Dear customer, please verify your account.")
        assert ok is True

    def test_empty_text(self):
        ok, _ = validate_email_text("")
        assert ok is False

    def test_whitespace_only(self):
        ok, _ = validate_email_text("   \n  ")
        assert ok is False

    def test_too_long(self):
        ok, _ = validate_email_text("a" * 60_000)
        assert ok is False


# ── heuristic_url_score ───────────────────────────────────────────────────

class TestHeuristicUrlScore:
    def test_clean_url_low_score(self):
        score = heuristic_url_score("https://google.com")
        assert score < 0.3

    def test_ip_url_higher_score(self):
        score = heuristic_url_score("http://192.168.1.1/login")
        assert score > 0.1

    def test_suspicious_tld_higher_score(self):
        score = heuristic_url_score("http://paypal.tk/verify")
        assert score > 0.2

    def test_score_capped_at_one(self):
        url = "http://192.168.1.1/login?verify=account@paypal.tk&update=payment&confirm=1&signin=true"
        score = heuristic_url_score(url)
        assert 0.0 <= score <= 1.0

    def test_https_scores_lower_than_http(self):
        https_score = heuristic_url_score("https://google.com")
        http_score  = heuristic_url_score("http://google.com")
        assert https_score <= http_score


# ── heuristic_email_score ─────────────────────────────────────────────────

class TestHeuristicEmailScore:
    def test_phishing_keywords_increase_score(self):
        text  = "Dear customer, your account has been suspended. Click here immediately to verify your account."
        score = heuristic_email_score(text)
        assert score > 0.0

    def test_clean_email_low_score(self):
        text  = "Hi team, please find the quarterly report attached."
        score = heuristic_email_score(text)
        assert score == 0.0

    def test_score_capped_at_one(self):
        text = " ".join(["verify your account", "update your payment", "click here immediately",
                         "bank account", "your account has been suspended", "confirm your identity",
                         "unusual sign-in activity", "dear customer", "prize winner", "password reset",
                         "unauthorized access", "limited time offer"])
        score = heuristic_email_score(text)
        assert score <= 1.0


# ── compute_verdict ───────────────────────────────────────────────────────

class TestComputeVerdict:
    def test_low_score_safe(self):
        assert compute_verdict(0.10) == "safe"
        assert compute_verdict(0.34) == "safe"

    def test_mid_score_suspicious(self):
        assert compute_verdict(0.35) == "suspicious"
        assert compute_verdict(0.64) == "suspicious"

    def test_high_score_phishing(self):
        assert compute_verdict(0.65) == "phishing"
        assert compute_verdict(1.00) == "phishing"
