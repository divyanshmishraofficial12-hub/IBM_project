"""
utils.py — Citizen Cyber Defense & Digital Forensics Intelligence Utilities.
Provides:
  - Shannon Entropy (DGA & Gibberish Detection)
  - TLD & Domain Structural Integrity Checking (catches missing/invalid TLDs like https://gjgku)
  - Levenshtein Brand Typosquatting & Homoglyph Radar
  - UPI Payment Intent & Quishing Fraud Analysis
  - Everyday WhatsApp / SMS Social Engineering Scam Classifier
  - Safe URL Unshortener & Redirection Sandbox
  - SHA-256 Digital Evidence Hashing (Forensic Chain-of-Custody)
  - MITRE ATT&CK Threat Mapping
"""

import math
import re
import html
import hashlib
from difflib import SequenceMatcher
from urllib.parse import urlparse, parse_qs, unquote
import requests


# ---------------------------------------------------------------------------
# 1. Sanitization & Input Validation
# ---------------------------------------------------------------------------

def sanitize_input(text: str, max_length: int = 4096) -> str:
    """Strip dangerous characters and limit length."""
    if not isinstance(text, str):
        raise ValueError("Input must be a string.")
    text = text[:max_length]
    try:
        import bleach
        text = bleach.clean(text, tags=[], attributes={}, strip=True)
    except ImportError:
        text = html.escape(text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return text.strip()


_URL_REGEX = re.compile(r"^https?://", re.IGNORECASE)

def validate_url(url: str) -> tuple[bool, str]:
    """Validate that a string is a parsable HTTP/HTTPS URL."""
    if not url:
        return False, "URL cannot be empty."
    if not _URL_REGEX.match(url):
        return False, "URL must start with http:// or https://"
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Failed to parse URL."
    if not parsed.netloc:
        return False, "URL is missing a valid host."
    if len(url) > 2048:
        return False, "URL exceeds maximum allowed length (2048 chars)."
    return True, "OK"


def validate_email_text(text: str) -> tuple[bool, str]:
    if not text or not text.strip():
        return False, "Input text cannot be empty."
    if len(text) > 50_000:
        return False, "Input text exceeds maximum allowed length (50 000 chars)."
    return True, "OK"


# ---------------------------------------------------------------------------
# 2. Shannon Entropy & DGA / Gibberish Detection
# ---------------------------------------------------------------------------

def calculate_shannon_entropy(text: str) -> float:
    """
    Compute Shannon Entropy (bits per character) of a string.
    High entropy indicates random/algorithmic generation (DGA) or encrypted/obfuscated strings.
    """
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def detect_dga_gibberish(domain: str) -> tuple[bool, float, str]:
    """
    Detect Domain Generation Algorithm (DGA) or gibberish input.
    Analyzes:
      1. Shannon Entropy
      2. Vowel-to-Consonant Ratio
      3. Consecutive Consonant Clusters (e.g., 'gjgk')
    Returns: (is_dga: bool, score: float, reason: str)
    """
    clean_domain = domain.lower().split(":")[0]
    # Remove standard tld if present
    parts = clean_domain.split(".")
    core = parts[0] if parts else clean_domain

    if len(core) < 4:
        return False, 0.0, "Short domain"

    entropy = calculate_shannon_entropy(core)
    vowels = len(re.findall(r"[aeiou]", core))
    consonants = len(re.findall(r"[bcdfghjklmnpqrstvwxyz]", core))
    digits = len(re.findall(r"[0-9]", core))

    # Abnormal ratio checks:
    # 1. Zero vowels in words >= 5 characters (e.g. 'gjgku' has 1 vowel 'u' and 4 consonants 'gjgk')
    consonant_cluster = bool(re.search(r"[bcdfghjklmnpqrstvwxyz]{4,}", core))
    vowel_ratio = vowels / (len(core) or 1)

    is_dga = False
    reasons = []
    dga_score = 0.0

    if entropy >= 3.2 and len(core) >= 8:
        is_dga = True
        dga_score += 0.4
        reasons.append(f"High Shannon entropy ({entropy})")
    elif entropy >= 2.2 and len(core) >= 5 and consonant_cluster:
        is_dga = True
        dga_score += 0.45
        reasons.append("High consonant cluster anomaly")

    if consonant_cluster:
        dga_score += 0.3
        reasons.append("Abnormal consonant cluster (gibberish/DGA pattern)")

    if vowel_ratio < 0.2 and len(core) >= 5:
        dga_score += 0.25
        reasons.append("Unusually low vowel ratio")

    return is_dga, min(round(dga_score, 2), 1.0), "; ".join(reasons) if reasons else "Normal lexical structure"


# ---------------------------------------------------------------------------
# 3. TLD & Host Structural Verification (Fixes https://gjgku)
# ---------------------------------------------------------------------------

COMMON_LEGIT_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int", "in", "co.in", "co.uk",
    "io", "ai", "app", "dev", "me", "co", "info", "biz", "de", "jp", "uk",
    "ca", "au", "fr", "tech", "online", "store", "site", "live", "cloud",
}

HIGH_ABUSE_PHISHING_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "click",
    "icu", "fit", "rest", "cam", "work", "date", "racing", "surf", "country",
}


def analyze_domain_structure(netloc: str) -> dict:
    """
    Checks hostname structure:
      - Valid dot-delimited domain with recognized TLD?
      - Missing TLD (e.g. 'gjgku') -> Critical structural red flag!
      - Suspicious/Abuse TLD?
      - Raw IP address?
    """
    host = netloc.split(":")[0].lower().strip()
    result = {
        "host": host,
        "is_ip": bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host)),
        "has_dot": "." in host,
        "missing_tld": False,
        "is_abuse_tld": False,
        "tld": "",
        "structural_risk": 0.0,
        "notes": [],
    }

    if result["is_ip"]:
        result["structural_risk"] += 0.40
        result["notes"].append("Host is a raw numerical IP address (often used to bypass domain reputation).")
        return result

    if not result["has_dot"]:
        # Domain has NO dots at all (like 'https://gjgku')
        result["missing_tld"] = True
        result["structural_risk"] += 0.65
        result["notes"].append("CRITICAL: Domain has NO valid Top-Level Domain (TLD). It cannot resolve to a standard public website.")
        return result

    # Extract TLD
    parts = host.split(".")
    tld = parts[-1]
    if len(parts) >= 2 and f"{parts[-2]}.{parts[-1]}" in COMMON_LEGIT_TLDS:
        tld = f"{parts[-2]}.{parts[-1]}"
    result["tld"] = tld

    if tld in HIGH_ABUSE_PHISHING_TLDS:
        result["is_abuse_tld"] = True
        result["structural_risk"] += 0.35
        result["notes"].append(f"Uses high-abuse phishing TLD (.{tld}).")
    elif len(tld) < 2 or not tld.isalpha():
        result["structural_risk"] += 0.40
        result["notes"].append(f"Malformed or unrecognized TLD (.{tld}).")

    if len(parts) > 4:
        result["structural_risk"] += 0.20
        result["notes"].append(f"Excessive subdomain depth ({len(parts)-1} levels).")

    return result


# ---------------------------------------------------------------------------
# 4. Brand Typosquatting & Homoglyph Radar
# ---------------------------------------------------------------------------

TARGETED_BRANDS = [
    "google", "microsoft", "apple", "amazon", "paypal", "netflix",
    "facebook", "instagram", "whatsapp", "telegram", "twitter", "linkedin",
    "chase", "wellsfargo", "bankofamerica", "citibank", "capitalone",
    "sbi", "hdfc", "icicibank", "axisbank", "punjabnationalbank",
    "phonepe", "paytm", "googlepay", "bhim", "cred",
    "binance", "coinbase", "metamask", "kraken",
    "dropbox", "adobe", "github", "gitlab", "steam", "spotify",
]

HOMOGLYPH_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "@": "a",
    "vv": "w", "rn": "m", "cl": "d",
}


def normalize_homoglyphs(text: str) -> str:
    """Normalize common visual character substitutions."""
    res = text.lower()
    for sub, rep in HOMOGLYPH_MAP.items():
        res = res.replace(sub, rep)
    return res


def check_brand_typosquatting(domain: str) -> dict:
    """
    Check if a domain is spoofing or typosquatting a known brand.
    Returns details on impersonated brand and similarity score.
    """
    clean_host = domain.lower().split(":")[0]
    parts = clean_host.split(".")
    domain_body = parts[0] if parts else clean_host
    normalized_body = normalize_homoglyphs(domain_body)

    best_match = None
    highest_sim = 0.0

    for brand in TARGETED_BRANDS:
        # Exact brand match in subdomains or suspicious context
        if brand in domain_body:
            # Check if domain IS the official brand domain
            if clean_host == f"{brand}.com" or clean_host.endswith(f".{brand}.com") or clean_host == f"{brand}.in":
                return {"is_spoof": False, "matched_brand": brand, "similarity": 1.0, "is_official": True}
            else:
                return {
                    "is_spoof": True,
                    "matched_brand": brand,
                    "similarity": 1.0,
                    "is_official": False,
                    "reason": f"Brand name '{brand}' embedded in unofficial domain '{clean_host}'",
                }

        # Check fuzzy similarity with normalized text
        sim = SequenceMatcher(None, normalized_body, brand).ratio()
        if sim > highest_sim:
            highest_sim = sim
            best_match = brand

    if highest_sim >= 0.78 and best_match and highest_sim < 1.0:
        return {
            "is_spoof": True,
            "matched_brand": best_match,
            "similarity": round(highest_sim, 2),
            "is_official": False,
            "reason": f"High typosquatting similarity ({round(highest_sim*100)}%) to '{best_match}' (e.g. lookalike letters)",
        }

    return {"is_spoof": False, "matched_brand": None, "similarity": round(highest_sim, 2), "is_official": False}


# ---------------------------------------------------------------------------
# 5. UPI & Payment Intent Inspector (Everyday Citizen Protection)
# ---------------------------------------------------------------------------

def parse_upi_intent(raw_str: str) -> dict:
    """
    Parses and audits a UPI deep-link or QR code payload (e.g. upi://pay?pa=...).
    Protects citizens against the classic 'Scan to receive payment' fraud.
    """
    if not raw_str or not raw_str.startswith("upi://pay"):
        return {"is_upi": False}

    parsed = urlparse(raw_str)
    params = parse_qs(parsed.query)

    pa = params.get("pa", [""])[0]     # Payee Virtual Address
    pn = params.get("pn", [""])[0]     # Payee Name
    am = params.get("am", [""])[0]     # Amount
    tn = params.get("tn", [""])[0]     # Transaction Note
    mc = params.get("mc", [""])[0]     # Merchant Code

    is_dangerous = False
    warning_title = ""
    warning_details = []

    # Golden Rule of UPI: Entering PIN or scanning a UPI pay intent ALWAYS DEDUCTS MONEY
    is_dangerous = True
    warning_title = "🚨 CRITICAL UPI FINANCIAL TRAP: This QR code is configured to WITHDRAW/PAY money!"
    warning_details.append(
        "REMEMBER: You NEVER need to scan a QR code or enter your UPI PIN to RECEIVE money. "
        "Scanning this code in PhonePe/GooglePay/Paytm will authorize money to LEAVE your bank account."
    )

    if am:
        warning_details.append(f"Requested Amount: ₹{am} will be debited from YOUR account.")

    # Check for social engineering in notes
    suspicious_notes = ["refund", "cashback", "lottery", "olx", "reward", "verification", "bonus", "winner"]
    if tn:
        lower_tn = tn.lower()
        for kw in suspicious_notes:
            if kw in lower_tn:
                warning_details.append(f"Suspicious transaction note lure detected: '{tn}' (used to trick victims into paying).")

    return {
        "is_upi": True,
        "payee_vpa": pa,
        "payee_name": unquote(pn) if pn else "Unknown Payee",
        "amount": am or "User-defined",
        "note": unquote(tn) if tn else "",
        "merchant_code": mc,
        "is_fraud_trap": is_dangerous,
        "verdict": "CRITICAL RISK",
        "warning_title": warning_title,
        "warning_details": warning_details,
        "safety_rule": "NEVER enter your UPI PIN unless you intend to pay someone. Entering your PIN never deposits money.",
    }


# ---------------------------------------------------------------------------
# 6. Everyday WhatsApp / SMS Social Engineering Scam Classifier
# ---------------------------------------------------------------------------

SCAM_ARCHETYPES = {
    "ELECTRICITY_BILL_SCAM": {
        "name": "⚡ Electricity / Utility Disconnection Scam",
        "patterns": [
            r"electricity.*disconnect", r"power.*cut", r"bill.*unpaid",
            r"tonight at (?:9:30|8:30|9|10)", r"contact.*officer", r"call immediately.*bill",
        ],
        "risk_level": "CRITICAL",
        "advice": [
            "Electricity boards NEVER send personal WhatsApp or mobile SMS threats to cut power tonight.",
            "Do NOT call the phone number provided in the message.",
            "Check your official state power utility app or electricity bill directly.",
            "Report immediately to 1930 and Sanchar Saathi Chakshu.",
        ]
    },
    "BANK_KYC_PAN_BLOCKED": {
        "name": "🏦 Bank Account / KYC / PAN Suspension Fraud",
        "patterns": [
            r"account.*block", r"kyc.*expired", r"pan.*card.*update",
            r"sbi.*reward", r"hdfc.*suspended", r"icici.*deactivated",
            r"click here to update kyc", r"netbanking.*disabled",
        ],
        "risk_level": "CRITICAL",
        "advice": [
            "Banks NEVER ask you to update KYC or link PAN through unofficial web links or APK files.",
            "Never share OTP, passwords, or debit card CVV with anyone.",
            "Visit your official bank branch or log in only through the official banking app.",
        ]
    },
    "PART_TIME_JOB_FRAUD": {
        "name": "💼 Part-Time Telegram / YouTube Task Job Scam",
        "patterns": [
            r"part[- ]time job", r"earn (?:rs\.?|inr|₹)?\s?[1-9]\d{3}",
            r"like youtube video", r"daily payment", r"work from home.*simple task",
            r"contact.*telegram", r"t\.me/",
        ],
        "risk_level": "HIGH",
        "advice": [
            "No legitimate company pays ₹3,000–₹5,000 per day for liking videos or rating hotels.",
            "Scammers pay a tiny token first, then trap victims into 'prepaid investment' tasks worth lakhs.",
            "Block the sender and report the Telegram handle to Cyber Crime.",
        ]
    },
    "PARCEL_COURIER_TRAP": {
        "name": "📦 Postal / Customs / Courier Delivery Trap",
        "patterns": [
            r"india post.*delivery", r"package.*stuck", r"address.*incomplete",
            r"customs.*duty", r"delivery failed.*update address",
        ],
        "risk_level": "HIGH",
        "advice": [
            "Postal services do not ask for debit card payments via random SMS links for failed address verification.",
            "Always track parcels using the official tracking number on the official courier portal.",
        ]
    },
    "DIGITAL_ARREST_EXTORTION": {
        "name": "⚖️ Fake Police / CBI 'Digital Arrest' Extortion",
        "patterns": [
            r"digital arrest", r"police.*warrant", r"cbi.*investigation",
            r"parcel.*drugs", r"narcotics.*money laundering", r"video call.*interrogation",
        ],
        "risk_level": "CRITICAL",
        "advice": [
            "There is NO SUCH LEGAL CONCEPT as 'Digital Arrest' under Indian Law or global law enforcement.",
            "Police, CBI, Customs, and Judges NEVER conduct trials or demand money via WhatsApp/Skype video calls.",
            "Disconnect the call immediately and dial 1930 or your local police station.",
        ]
    },
}


def classify_scam_message(text: str) -> dict:
    """
    Classify everyday SMS, WhatsApp forwards, and emails into actionable scam archetypes.
    Returns: category, risk_score, matched_indicators, and everyday safety checklist.
    """
    lower = text.lower()
    matched_categories = []
    red_flags = []
    score = 0.0

    for cat_id, data in SCAM_ARCHETYPES.items():
        cat_matches = 0
        for pat in data["patterns"]:
            if re.search(pat, lower):
                cat_matches += 1
                red_flags.append(f"Matched threat pattern: '{pat}' in {data['name']}")
        if cat_matches > 0:
            matched_categories.append({
                "category_id": cat_id,
                "name": data["name"],
                "risk_level": data["risk_level"],
                "advice": data["advice"],
                "matches": cat_matches,
            })
            score += 0.35 + (cat_matches * 0.15)

    # General urgency & phishing cues
    urgency_patterns = [
        "immediately", "within 24 hours", "urgent action required",
        "account closed today", "action required immediately",
    ]
    for p in urgency_patterns:
        if p in lower:
            score += 0.15
            red_flags.append(f"Artificial urgency trigger: '{p}'")

    # Link presence
    urls_found = re.findall(r"https?://\S+|www\.\S+|bit\.ly/\S+|tinyurl\.com/\S+", text)
    if urls_found:
        score += 0.20
        red_flags.append(f"Contains unverified action link(s): {', '.join(urls_found[:3])}")

    score = min(round(score, 2), 1.0)
    verdict = "phishing" if score >= 0.55 else ("suspicious" if score >= 0.30 else "safe")

    primary_category = matched_categories[0] if matched_categories else {
        "category_id": "GENERAL_MESSAGE",
        "name": "General Communication / Unclassified",
        "risk_level": "LOW",
        "advice": ["Stay alert before clicking any links or sharing sensitive personal data."],
    }

    return {
        "verdict": verdict,
        "scam_score": score,
        "primary_category": primary_category,
        "matched_categories": matched_categories,
        "red_flags": red_flags,
        "urls_detected": urls_found,
        "action_checklist": primary_category["advice"],
        "emergency_helpline": "Call 1930 (National Cyber Crime Helpline) or report at https://cybercrime.gov.in",
    }


# ---------------------------------------------------------------------------
# 7. Safe URL Unshortener & Redirection Sandbox
# ---------------------------------------------------------------------------

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "ow.ly", "buff.ly", "t.ly", "wa.me", "v.gd", "qr.ae",
}


def safe_unshorten_url(url: str, max_redirects: int = 5, timeout: int = 4) -> dict:
    """
    Safely resolves shortened or redirecting URLs without executing client code.
    Returns destination chain and reveals masked targets.
    """
    chain = [url]
    current = url
    headers = {"User-Agent": "PhishGuard-Forensics-Sandbox/2.0 (Security-Verification)"}

    try:
        session = requests.Session()
        for _ in range(max_redirects):
            parsed = urlparse(current)
            resp = session.head(current, headers=headers, allow_redirects=False, timeout=timeout)
            if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
                next_url = resp.headers["Location"]
                if not next_url.startswith("http"):
                    # Relative redirect
                    next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"
                chain.append(next_url)
                current = next_url
            else:
                break
    except Exception as exc:
        return {
            "original_url": url,
            "final_url": current,
            "redirect_chain": chain,
            "was_redirected": len(chain) > 1,
            "resolution_error": str(exc),
        }

    return {
        "original_url": url,
        "final_url": current,
        "redirect_chain": chain,
        "was_redirected": len(chain) > 1,
        "resolution_error": None,
    }


# ---------------------------------------------------------------------------
# 8. Digital Forensics Artifacts & MITRE ATT&CK Mapping
# ---------------------------------------------------------------------------

def generate_evidence_hash(target_content: str) -> str:
    """Generate SHA-256 digital evidence hash for forensic chain-of-custody."""
    return hashlib.sha256(target_content.encode("utf-8", errors="ignore")).hexdigest()


def map_mitre_attack(signals: list) -> list:
    """Maps detected signals to MITRE ATT&CK enterprise techniques."""
    mitre = []
    text = " ".join(signals).lower()

    if any(k in text for k in ["missing tld", "dga", "entropy"]):
        mitre.append({
            "id": "T1568.002",
            "name": "Domain Generation Algorithms (DGA)",
            "tactic": "Command and Control",
            "url": "https://attack.mitre.org/techniques/T1568/002/",
        })

    if any(k in text for k in ["typosquat", "spoof", "homoglyph"]):
        mitre.append({
            "id": "T1583.001",
            "name": "Acquire Infrastructure: Domains (Typosquatting)",
            "tactic": "Resource Development",
            "url": "https://attack.mitre.org/techniques/T1583/001/",
        })

    if any(k in text for k in ["qr", "upi", "quishing"]):
        mitre.append({
            "id": "T1566.001",
            "name": "Phishing: Spearphishing Attachment / Quishing",
            "tactic": "Initial Access",
            "url": "https://attack.mitre.org/techniques/T1566/001/",
        })

    if any(k in text for k in ["link", "redirect", "url", "unshorten"]):
        mitre.append({
            "id": "T1566.002",
            "name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access",
            "url": "https://attack.mitre.org/techniques/T1566/002/",
        })

    if any(k in text for k in ["kyc", "electricity", "urgency", "arrest"]):
        mitre.append({
            "id": "T1204.001",
            "name": "User Execution: Malicious Link & Social Engineering",
            "tactic": "Execution",
            "url": "https://attack.mitre.org/techniques/T1204/001/",
        })

    return mitre


# ---------------------------------------------------------------------------
# 9. Unified Heuristic URL & Email Scores
# ---------------------------------------------------------------------------

def heuristic_url_score(url: str) -> float:
    """
    Advanced multi-layered heuristic score for URL:
      - TLD & Host structural integrity (catches 'https://gjgku')
      - DGA & Shannon entropy
      - Brand typosquatting radar
      - Suspicious patterns & abuse TLDs
    """
    score = 0.0
    parsed = urlparse(url)
    host = parsed.netloc

    # 1. Structural audit
    structure = analyze_domain_structure(host)
    score += structure["structural_risk"]

    # 2. DGA / Gibberish audit
    is_dga, dga_weight, _ = detect_dga_gibberish(host)
    if is_dga:
        score += dga_weight

    # 3. Brand Typosquatting
    brand_check = check_brand_typosquatting(host)
    if brand_check["is_spoof"]:
        score += 0.45

    # 4. HTTPS absence
    if parsed.scheme != "https":
        score += 0.10

    # 5. IP Address
    if structure["is_ip"]:
        score += 0.35

    # 6. Specific credential solicitation keywords in path
    path = parsed.path.lower() + "?" + parsed.query.lower()
    for kw in ["verify", "login", "signin", "banking", "secure", "update", "wallet", "recover"]:
        if kw in path:
            score += 0.10

    return min(round(score, 2), 1.0)


def heuristic_email_score(text: str) -> float:
    """Heuristic score for email or message content."""
    res = classify_scam_message(text)
    return res["scam_score"]


def compute_verdict(risk_score: float) -> str:
    """Map 0-1 risk score to verdict."""
    if risk_score < 0.35:
        return "safe"
    if risk_score < 0.65:
        return "suspicious"
    return "phishing"
