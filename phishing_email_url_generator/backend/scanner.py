"""
scanner.py — PhishGuard AI Threat Intelligence & Digital Forensics Inference Engine.
Combines:
  - 22-Feature Machine Learning Inference (RandomForest)
  - Shannon Entropy & DGA / Gibberish Detection
  - TLD & Domain Structural Verification (catches missing TLDs like https://gjgku)
  - Levenshtein Brand Typosquatting & Impersonation Radar
  - Safe Redirection Unshortener Sandbox
  - Everyday WhatsApp / SMS Social Engineering Scam Triage
  - UPI Payment Trap & Quishing Intent Analysis
  - MITRE ATT&CK Enterprise Technique Mapping
  - SHA-256 Digital Evidence Hash (Forensic Chain-of-Custody)
"""

import os
import logging
import joblib
import re
import requests
from pathlib import Path
from urllib.parse import urlparse

from utils import (
    calculate_shannon_entropy,
    detect_dga_gibberish,
    analyze_domain_structure,
    check_brand_typosquatting,
    parse_upi_intent,
    classify_scam_message,
    safe_unshorten_url,
    generate_evidence_hash,
    map_mitre_attack,
    heuristic_url_score,
    heuristic_email_score,
    compute_verdict,
    SHORTENER_DOMAINS,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------

_BACKEND_DIR      = Path(__file__).parent
_URL_MODEL_PATH   = _BACKEND_DIR / "url_model.pkl"
_EMAIL_MODEL_PATH = _BACKEND_DIR / "email_model.pkl"

_url_model   = None
_email_model = None


def load_model():
    """Load both ML models once at startup."""
    global _url_model, _email_model

    for attr, path, label in [
        ("_url_model",   _URL_MODEL_PATH,   "URL model"),
        ("_email_model", _EMAIL_MODEL_PATH, "Email model"),
    ]:
        if path.exists():
            try:
                m = joblib.load(path)
                globals()[attr] = m
                logger.info("%s loaded from %s", label, path)
            except Exception as exc:
                logger.warning("Could not load %s: %s — using heuristics.", path, exc)
        else:
            logger.warning("%s not found at %s — using heuristics.", label, path)


def _extract_url_features(url: str) -> list:
    """Rich 22-dimensional feature vector matching train_model.py."""
    parsed = urlparse(url)
    host = parsed.netloc or ""
    structure = analyze_domain_structure(host)
    is_dga, dga_score, _ = detect_dga_gibberish(host)
    brand_check = check_brand_typosquatting(host)
    clean_host = host.lower().split(":")[0]

    return [
        len(url),
        url.count("."),
        url.count("-"),
        url.count("@"),
        url.count("//"),
        url.count("?"),
        url.count("="),
        url.count("&"),
        int(parsed.scheme == "https"),
        len(host),
        host.count("."),
        int(bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host))),
        calculate_shannon_entropy(host),
        int(is_dga),
        dga_score,
        int(structure["missing_tld"]),
        int(structure["is_abuse_tld"]),
        structure["structural_risk"],
        int(brand_check["is_spoof"]),
        brand_check["similarity"],
        int(clean_host in SHORTENER_DOMAINS),
        int(any(kw in url.lower() for kw in ["login", "verify", "secure", "account", "update", "bank", "pay", "kyc", "bill"])),
    ]


def _ml_score_url(url: str) -> float | None:
    if _url_model is None:
        return None
    try:
        features = _extract_url_features(url)
        prob = _url_model.predict_proba([features])[0][1]   # P(phishing)
        return float(prob)
    except Exception as exc:
        logger.error("ML URL inference error: %s", exc)
        return None


def _ml_score_email(text: str) -> float | None:
    if _email_model is None:
        return None
    try:
        prob = _email_model.predict_proba([text])[0][1]
        return float(prob)
    except Exception as exc:
        logger.error("ML email inference error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# External Threat Intelligence APIs (Optional free tiers)
# ---------------------------------------------------------------------------

def _check_google_safe_browsing(url: str) -> bool:
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    if not api_key or api_key == "YOUR_GSB_API_KEY_HERE":
        return False
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "2.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=4)
        resp.raise_for_status()
        return bool(resp.json().get("matches"))
    except Exception:
        return False


def _check_virustotal(url: str) -> int:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key or api_key == "YOUR_VT_API_KEY_HERE":
        return 0
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(endpoint, headers=headers, timeout=5)
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0) + stats.get("suspicious", 0)
    except Exception:
        pass
    return 0


# ---------------------------------------------------------------------------
# Primary Scanning & Forensics Pipelines
# ---------------------------------------------------------------------------

def scan_url(url: str) -> dict:
    """
    Comprehensive threat analysis for a URL.
    Handles unshortening, Shannon entropy, DGA detection, missing TLDs (e.g. gjgku),
    brand typosquatting, MITRE ATT&CK mapping, and XAI factor breakdown.
    """
    evidence_hash = generate_evidence_hash(url)
    parsed = urlparse(url)
    host = parsed.netloc or ""
    clean_host = host.lower().split(":")[0]

    # 1. Unshortener Sandbox if URL shortener detected
    unshorten_res = None
    target_url = url
    if clean_host in SHORTENER_DOMAINS:
        unshorten_res = safe_unshorten_url(url)
        target_url = unshorten_res["final_url"]

    # 2. Structural & Lexical Forensics
    structure = analyze_domain_structure(host)
    entropy_val = calculate_shannon_entropy(host)
    is_dga, dga_score, dga_reason = detect_dga_gibberish(host)
    brand_check = check_brand_typosquatting(host)

    # 3. Model & Heuristic scoring
    ml_raw    = _ml_score_url(target_url)
    heuristic = heuristic_url_score(target_url)
    gsb_hit   = _check_google_safe_browsing(target_url)
    vt_hits   = _check_virustotal(target_url)

    vt_score    = min(vt_hits / 10.0, 1.0)
    intel_score = max(float(gsb_hit), vt_score)

    # If critical structural failure (missing TLD like https://gjgku), guarantee high risk:
    if structure["missing_tld"]:
        risk_score = max(0.85, heuristic)
    elif is_dga and dga_score >= 0.4:
        risk_score = max(0.80, (ml_raw or heuristic))
    elif brand_check["is_spoof"]:
        risk_score = max(0.78, (ml_raw or heuristic))
    elif ml_raw is not None:
        risk_score = (ml_raw * 0.45) + (heuristic * 0.35) + (intel_score * 0.20)
    else:
        risk_score = (heuristic * 0.70) + (intel_score * 0.30)

    risk_score = round(min(risk_score, 1.0), 4)
    verdict    = compute_verdict(risk_score)

    # 4. Explainable AI (XAI) Factors
    factors = []
    signals = []

    if structure["missing_tld"]:
        factors.append({
            "severity": "CRITICAL",
            "title": "Missing or Invalid TLD",
            "description": f"Domain '{host}' has no recognized Top-Level Domain (e.g. .com, .org). It cannot resolve to a standard public website.",
        })
        signals.append("missing tld unresolvable")

    if structure["is_abuse_tld"]:
        factors.append({
            "severity": "HIGH",
            "title": "High-Abuse Phishing TLD",
            "description": f"Domain uses '.{structure['tld']}', a top-level domain frequently abused by bulk phishing and malware campaigns.",
        })
        signals.append("abuse tld")

    if is_dga:
        factors.append({
            "severity": "HIGH",
            "title": "Algorithmic Gibberish / DGA Anomaly",
            "description": f"Domain exhibits abnormal lexical disorder (Shannon Entropy: {entropy_val}, {dga_reason}).",
        })
        signals.append("dga entropy")

    if brand_check["is_spoof"]:
        factors.append({
            "severity": "CRITICAL",
            "title": f"Brand Impersonation ({brand_check['matched_brand'].upper()})",
            "description": brand_check.get("reason", "Domain appears to mimic a well-known brand."),
        })
        signals.append("typosquat brand spoof")

    if structure["is_ip"]:
        factors.append({
            "severity": "MEDIUM",
            "title": "Direct Numerical IP Host",
            "description": "URL connects directly to an IP address without domain name registration.",
        })
        signals.append("ip address host")

    if parsed.scheme != "https":
        factors.append({
            "severity": "LOW",
            "title": "Unencrypted HTTP Protocol",
            "description": "Communication is unencrypted and vulnerable to eavesdropping.",
        })
        signals.append("unencrypted http")

    if unshorten_res and unshorten_res["was_redirected"]:
        factors.append({
            "severity": "MEDIUM",
            "title": "Obfuscated Redirect Chain",
            "description": f"URL masks destination via shortener: redirected from '{url}' to '{target_url}'.",
        })
        signals.append("url redirect unshorten")

    if not factors:
        factors.append({
            "severity": "CLEAN",
            "title": "Standard Structural Integrity",
            "description": f"Domain '{host}' has a recognized TLD, normal character entropy ({entropy_val}), and no impersonation markers.",
        })

    # 5. MITRE ATT&CK Mapping
    mitre_attack = map_mitre_attack(signals)

    # 6. Citizen & SOC Advice
    citizen_advice = []
    if verdict == "phishing":
        citizen_advice = [
            "🚨 DO NOT open this link on your computer or phone.",
            "❌ NEVER enter passwords, OTPs, or banking details on this destination.",
            "🛡️ If received via SMS or WhatsApp, block the sender and report to 1930 (National Cyber Crime Helpline).",
        ]
    elif verdict == "suspicious":
        citizen_advice = [
            "⚠️ Exercise caution: Domain exhibits irregularities.",
            "🔍 Verify the sender's identity through official channels before proceeding.",
        ]
    else:
        citizen_advice = [
            "✅ Link structure appears normal. Always check for HTTPS and URL spelling before entering credentials.",
        ]

    return {
        "risk_score":       risk_score,
        "verdict":          verdict,
        "ml_score":         round(ml_raw, 4) if ml_raw is not None else None,
        "heuristic_score":  round(heuristic, 4),
        "evidence_hash":    evidence_hash,
        "shannon_entropy":  entropy_val,
        "dga_detected":     is_dga,
        "brand_spoof":      brand_check,
        "domain_structure": structure,
        "unshorten":        unshorten_res,
        "explainable_factors": factors,
        "mitre_attack":     mitre_attack,
        "citizen_advice":   citizen_advice,
        "gsb_flagged":      gsb_hit,
        "vt_positives":     vt_hits,
        "details": {
            "ml_available": _url_model is not None,
            "gsb_enabled":  bool(os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")),
            "vt_enabled":   bool(os.getenv("VIRUSTOTAL_API_KEY")),
        },
    }


def scan_email(email_text: str) -> dict:
    """
    Phishing analysis pipeline for email body text.
    Combines ML inference, scam archetype classification, and forensic evidence hashing.
    """
    evidence_hash = generate_evidence_hash(email_text)
    scam_report   = classify_scam_message(email_text)
    ml_raw        = _ml_score_email(email_text)
    heuristic     = scam_report["scam_score"]

    if ml_raw is not None:
        risk_score = (ml_raw * 0.50) + (heuristic * 0.50)
    else:
        risk_score = heuristic

    risk_score = round(min(risk_score, 1.0), 4)
    verdict    = compute_verdict(risk_score)

    signals = [scam_report["primary_category"]["name"]] + scam_report["red_flags"]
    mitre_attack = map_mitre_attack(signals)

    factors = []
    for flag in scam_report["red_flags"]:
        factors.append({
            "severity": "HIGH",
            "title": "Social Engineering Indicator",
            "description": flag,
        })
    if not factors:
        factors.append({
            "severity": "CLEAN",
            "title": "No Coercive Triggers",
            "description": "Text lacks artificial urgency, extortion threats, or credential solicitation patterns.",
        })

    return {
        "risk_score":          risk_score,
        "verdict":             verdict,
        "ml_score":            round(ml_raw, 4) if ml_raw is not None else None,
        "heuristic_score":     round(heuristic, 4),
        "evidence_hash":       evidence_hash,
        "scam_category":       scam_report["primary_category"]["name"],
        "explainable_factors": factors,
        "mitre_attack":        mitre_attack,
        "citizen_advice":      scam_report["action_checklist"],
        "emergency_helpline":  scam_report["emergency_helpline"],
        "details": {
            "ml_available": _email_model is not None,
            "gsb_enabled":  False,
            "vt_enabled":   False,
        },
    }


def scan_message(message_text: str) -> dict:
    """
    Dedicated Citizen Anti-Fraud endpoint for WhatsApp, SMS, and chat messages.
    """
    return scan_email(message_text)


def scan_upi_qr(raw_payload: str) -> dict:
    """
    Citizen Protection Inspector for QR Codes and UPI payment payloads.
    Analyzes whether a QR code is a UPI debit trap or phishing link.
    """
    evidence_hash = generate_evidence_hash(raw_payload)

    # 1. Check if UPI intent
    if raw_payload.startswith("upi://pay"):
        upi_data = parse_upi_intent(raw_payload)
        mitre = [{
            "id": "T1566.001",
            "name": "Phishing: Spearphishing Attachment / Quishing",
            "tactic": "Initial Access",
            "url": "https://attack.mitre.org/techniques/T1566/001/",
        }]
        return {
            "payload_type": "UPI_PAYMENT_INTENT",
            "verdict": "CRITICAL RISK",
            "risk_score": 0.95,
            "evidence_hash": evidence_hash,
            "upi_analysis": upi_data,
            "explainable_factors": [{
                "severity": "CRITICAL",
                "title": "UPI Debit / Payment Withdrawal Trap",
                "description": upi_data["warning_title"],
            }],
            "citizen_advice": [
                "⚠️ DO NOT SCAN THIS QR CODE IN GOOGLEPAY, PHONEPE, OR PAYTM.",
                "❌ You NEVER need to enter a UPI PIN or scan a QR code to receive money or refunds.",
                "🛡️ Entering your PIN will instantly deduct money from your bank account.",
            ],
            "mitre_attack": mitre,
        }

    # 2. Check if URL embedded in QR
    if raw_payload.startswith("http://") or raw_payload.startswith("https://"):
        url_scan = scan_url(raw_payload)
        url_scan["payload_type"] = "QUISHING_URL"
        url_scan["quishing_warning"] = "QR code contains a web destination (Quishing attack vector)."
        return url_scan

    # 3. Plain text payload
    msg_scan = scan_message(raw_payload)
    msg_scan["payload_type"] = "TEXT_PAYLOAD"
    return msg_scan
