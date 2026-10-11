"""
train_model.py — Generate and train the PhishGuard AI detection models.
Produces:
  - url_model.pkl   : Enhanced RandomForestClassifier with 22 lexical, DGA, entropy & typosquat features
  - email_model.pkl : TF-IDF + LogisticRegression pipeline covering modern email, SMS, and WhatsApp scams

Run once to build or refresh models:
    python backend/train_model.py
"""

import random
import string
import logging
from pathlib import Path

import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

import sys
sys.path.insert(0, str(Path(__file__).parent))

from utils import (
    calculate_shannon_entropy,
    detect_dga_gibberish,
    analyze_domain_structure,
    check_brand_typosquatting,
    SHORTENER_DOMAINS,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

BACKEND_DIR = Path(__file__).parent if (Path(__file__).parent / "server.py").exists() else (Path(__file__).parent / "backend")
BACKEND_DIR.mkdir(exist_ok=True)

random.seed(42)
np.random.seed(42)


# ═══════════════════════════════════════════════════════════════════════════
# 1. URL FEATURE EXTRACTION & TRAINING
# ═══════════════════════════════════════════════════════════════════════════

def _extract_url_features(url: str) -> list:
    """
    Rich 22-dimensional feature vector for URL classification:
    - Lengths and symbol frequencies
    - Protocol & structure
    - Shannon Entropy (algorithmic disorder)
    - DGA gibberish score
    - TLD status (missing, valid, or abuse)
    - Brand typosquatting similarity
    - Shortener presence & credential lures
    """
    from urllib.parse import urlparse
    import re

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
        # Advanced SOTA Forensics Features:
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


LEGIT_DOMAINS = [
    "google.com", "github.com", "microsoft.com", "amazon.com", "apple.com",
    "stackoverflow.com", "wikipedia.org", "reddit.com", "linkedin.com",
    "youtube.com", "twitter.com", "facebook.com", "instagram.com",
    "bbc.co.uk", "nytimes.com", "theguardian.com", "medium.com",
    "npmjs.com", "pypi.org", "docs.python.org", "developer.mozilla.org",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "gov.in", "uidai.gov.in",
    "cloudflare.com", "stripe.com", "openai.com", "vercel.com",
]

LEGIT_PATHS = [
    "/", "/about", "/products", "/services", "/contact", "/blog",
    "/docs", "/api/v1/status", "/search?q=cybersecurity", "/user/settings",
    "/news/tech", "/articles/2026", "/download/latest", "/help/faq",
]

PHISHING_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".info", ".zip", ".mov", ".icu", ".fit"]
PHISHING_KEYWORDS = [
    "secure", "login", "verify", "update", "account", "banking",
    "confirm", "validate", "signin", "auth", "security", "alert",
    "kyc", "pan", "bill", "refund", "reward",
]
BRAND_NAMES = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "chase", "wellsfargo", "sbi", "hdfc", "phonepe", "paytm",
]
PHISHING_PATHS = [
    "/verify-account", "/login?redirect=true", "/update-payment",
    "/confirm-identity", "/secure/login.php", "/account-suspended",
    "/click-here?token=abc123", "/reset-password?id=1337",
    "/update-pan-kyc", "/electricity-bill-pay", "/claim-reward-cashback",
]


def _rand_str(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _rand_consonants(n=6):
    return "".join(random.choices("bcdfghjklmnpqrstvwxyz", k=n))


def generate_legit_url():
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    return f"https://{domain}{path}"


def generate_phishing_url():
    style = random.choice(["tld", "subdomain", "ip", "typosquat", "dga", "missing_tld", "long"])

    if style == "missing_tld":
        # Simulates inputs like 'https://gjgku' with no TLD
        gibberish = _rand_consonants(random.randint(5, 8))
        return f"https://{gibberish}"

    elif style == "dga":
        # Random DGA algorithm string on abuse TLD
        dga = _rand_consonants(random.randint(7, 12))
        tld = random.choice(PHISHING_TLDS)
        return f"http://{dga}{tld}/track"

    elif style == "typosquat":
        brand = random.choice(BRAND_NAMES)
        typo = brand.replace("a", "4").replace("o", "0").replace("i", "1").replace("e", "3")
        tld = random.choice([".com", ".net", ".xyz"])
        path = random.choice(PHISHING_PATHS)
        return f"http://{typo}{tld}{path}"

    elif style == "tld":
        brand = random.choice(BRAND_NAMES)
        tld = random.choice(PHISHING_TLDS)
        path = random.choice(PHISHING_PATHS)
        return f"http://{brand}{tld}{path}"

    elif style == "subdomain":
        brand = random.choice(BRAND_NAMES)
        fake = _rand_str(10)
        tld = random.choice([".com", ".net", ".org"])
        path = random.choice(PHISHING_PATHS)
        kw = random.choice(PHISHING_KEYWORDS)
        return f"http://{brand}-{kw}.{fake}{tld}{path}"

    elif style == "ip":
        ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        path = random.choice(PHISHING_PATHS)
        return f"http://{ip}{path}"

    else:
        fake_domain = _rand_str(15)
        tld = random.choice(PHISHING_TLDS)
        params = "&".join([f"{_rand_str(4)}={_rand_str(8)}" for _ in range(random.randint(3, 5))])
        return f"http://{fake_domain}{tld}/redirect?{params}"


def build_url_dataset(n_legit=3000, n_phishing=3000):
    X, y = [], []
    for _ in range(n_legit):
        url = generate_legit_url()
        X.append(_extract_url_features(url))
        y.append(0)
    for _ in range(n_phishing):
        url = generate_phishing_url()
        X.append(_extract_url_features(url))
        y.append(1)
    return np.array(X), np.array(y)


def train_url_model():
    logger.info("Building URL dataset with DGA, TLD, & Typosquatting features...")
    X, y = build_url_dataset(n_legit=3000, n_phishing=3000)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    logger.info("Training upgraded URL RandomForestClassifier...")
    clf = RandomForestClassifier(
        n_estimators=250,
        max_depth=16,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    logger.info("URL model evaluation:\n%s", classification_report(y_test, clf.predict(X_test)))

    out = BACKEND_DIR / "url_model.pkl"
    joblib.dump(clf, out)
    logger.info("✅ Saved URL Model: %s", out)
    return clf


# ═══════════════════════════════════════════════════════════════════════════
# 2. EMAIL & MESSAGE SCAM MODEL
# ═══════════════════════════════════════════════════════════════════════════

PHISHING_EMAIL_TEMPLATES = [
    # Classic Banking & Account Suspensions
    "Dear customer, your account has been suspended. Click here immediately to verify your identity and restore access.",
    "URGENT: Your bank account has been compromised. Update your payment information now to avoid suspension.",
    "Your PayPal account has unusual sign-in activity. Please verify your account details immediately.",
    "Security alert: Someone tried to log in to your account from a new device. Verify now.",
    "Action required: Your subscription expires today. Update your billing information to continue service.",
    "Your Apple ID has been locked due to suspicious activity. Click here to unlock your account.",
    "Amazon: Your order cannot be processed. Please update your payment method immediately.",
    # Everyday WhatsApp & SMS Scams
    "Electricity warning: Your power supply will be disconnected tonight at 9:30 PM because previous month bill is unpaid. Contact electricity officer immediately.",
    "Dear user, your electricity connection will be cut tonight at 9:30 PM due to pending bill. Call power officer now.",
    "Dear SBI customer, your bank account has been blocked due to pending PAN KYC. Click here to update your KYC immediately.",
    "HDFC Bank alert: Your netbanking is deactivated. Click the link to update your Aadhaar and PAN card.",
    "Earn Rs 3000 to Rs 5000 daily from home. Simple task like YouTube videos and Google reviews. Contact HR manager on Telegram @taskjob.",
    "Part time job opportunity: Work 30 minutes daily and earn Rs 3500. Message on WhatsApp for details.",
    "India Post: Your package could not be delivered due to incomplete address. Pay Rs 25 redelivery fee here.",
    "Customs department notice: Your parcel is held at international courier. Pay customs clearance immediately.",
    "Police notice: A courier containing illegal narcotics and fake passports was intercepted in your name. Join video call for investigation.",
    "Congratulations! You have won Rs 25,00,000 in KBC Lucky Draw. Claim your prize by paying verification charge.",
    "Claim your GooglePay ₹500 cashback reward! Scan this QR code and enter UPI PIN to receive money into your bank.",
]

LEGIT_EMAIL_TEMPLATES = [
    "Hi team, please find attached the meeting minutes from today's sprint planning session.",
    "Here is the monthly project update. We completed milestones 1 through 3 on schedule.",
    "Can we reschedule our 1:1 to tomorrow at 2 PM? Let me know if that time works for you.",
    "Thank you for your order! Your receipt is attached and your items are being prepared.",
    "Hi Alex, great work on the presentation yesterday. The client was very impressed with the demo.",
    "Reminder: The company all-hands meeting is this Thursday at 10 AM in the main auditorium.",
    "Your weekly GitHub digest is ready. Here are the top repositories trending in Python.",
    "The pull request #42 has been reviewed and approved. Ready to merge into main.",
    "Hi, I noticed a typo in the documentation on page 4. I submitted a quick fix for review.",
    "Welcome to our newsletter! Every Tuesday we share the latest news in web development.",
    "Your ride with Uber has completed. Total paid: $14.20. Rate your driver below.",
    "Your flight booking confirmation: PNR 8X9K2L. Check in opens 24 hours before departure.",
    "Your electricity bill for the month of March is Rs 1,420. Thank you for your online payment.",
]


def build_email_dataset(n_samples=2500):
    texts, labels = [], []
    for _ in range(n_samples):
        texts.append(random.choice(LEGIT_EMAIL_TEMPLATES))
        labels.append(0)
    for _ in range(n_samples):
        texts.append(random.choice(PHISHING_EMAIL_TEMPLATES))
        labels.append(1)
    return texts, labels


def train_email_model():
    logger.info("Building Email & Message scam dataset...")
    texts, labels = build_email_dataset(n_samples=2500)

    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42)

    logger.info("Training upgraded Email & Message TF-IDF Pipeline...")
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 3), max_features=8000, sublinear_tf=True)),
        ("clf",   LogisticRegression(C=5.0, max_iter=500, class_weight="balanced", random_state=42)),
    ])
    pipeline.fit(X_train, y_train)

    logger.info("Email model evaluation:\n%s", classification_report(y_test, pipeline.predict(X_test)))

    out = BACKEND_DIR / "email_model.pkl"
    joblib.dump(pipeline, out)
    logger.info("✅ Saved Email Model: %s", out)
    return pipeline


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    train_url_model()
    train_email_model()
    logger.info("🎯 All PhishGuard AI models successfully trained and ready!")
