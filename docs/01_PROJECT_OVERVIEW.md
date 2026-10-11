# 🛡️ PhishGuard — Project Overview

> **Simple Summary for Teachers & Evaluators:**  
> **PhishGuard** is an intelligent web-based cybersecurity platform that scans suspicious website URLs and email messages to detect phishing scams before they can deceive users. It uses a **Hybrid Detection Engine** combining Machine Learning (AI), Rule-Based Heuristics, and Threat Intelligence APIs.

---

## 1. Problem Statement
Every year, millions of students, employees, and everyday internet users fall victim to phishing attacks:
* Fake banking websites stealing credit card numbers and passwords.
* Urgent emails pretending to be from CEOs, colleges, or IT departments.
* Attackers disguise URLs using tricky characters (e.g., `micros0ft.com`, `paypa1.com`).

**Traditional antivirus and spam filters often fail** against brand-new ("zero-day") phishing links because they only check against a static blacklist of already-known bad links.

---

## 2. Our Solution: PhishGuard
PhishGuard does not just check a list — **it actively analyzes the behavior, structure, and text** of links and emails using a **3-Layer Hybrid Defense**:

```
+-------------------------------------------------------------------------+
|                              USER INTERACTION                           |
|       User pastes URL or Email text into Modern Glassmorphic Web App    |
+------------------------------------+------------------------------------+
                                     | (REST API via Fetch / JSON)
                                     v
+------------------------------------+------------------------------------+
|                         SECURITY & API GATEWAY                          |
|  • Input Sanitization (Bleach against XSS)                              |
|  • Rate Limiting (Flask-Limiter against spam/DoS)                       |
|  • JWT Authentication & Bcrypt Password Hashing                         |
+------------------------------------+------------------------------------+
                                     |
                                     v
+------------------------------------+------------------------------------+
|                      HYBRID DETECTION ENGINE (0 - 100)                  |
|                                                                         |
|   [ Layer 1: Machine Learning ]  40% Weight                             |
|   • URL Model: Random Forest Classifier (8 structural features)         |
|   • Email Model: TF-IDF Vectorizer + Logistic Regression                |
|                                                                         |
|   [ Layer 2: Heuristic Analysis ] 40% Weight                            |
|   • Detects IP-based URLs, Homoglyphs/Punycode, URL shorteners          |
|   • Checks urgent keywords, suspicious TLDs, credential harvesting      |
|                                                                         |
|   [ Layer 3: Threat Intelligence ] 20% Weight                           |
|   • Google Safe Browsing & VirusTotal API integrations                  |
+------------------------------------+------------------------------------+
                                     |
                                     v
+------------------------------------+------------------------------------+
|                             VERDICT & STORAGE                           |
|  • Risk Score: 0 - 100 (Safe 🟢 | Suspicious 🟡 | Phishing 🔴)           |
|  • Saved to SQLite Database (User Scan History & Stats)                 |
+-------------------------------------------------------------------------+
```

---

## 3. Technology Stack & Why We Chose Them

| Component | Technology | Why We Chose It |
|---|---|---|
| **Frontend** | HTML5, Vanilla CSS3, Modern JavaScript (ES6+) | Extremely fast, zero bloated npm packages, 100% responsive, dark-mode glassmorphic theme. |
| **Backend** | Python Flask 3.0 | Lightweight, secure, easy to explain, industry-standard for microservices and ML models. |
| **Machine Learning** | Scikit-Learn, NumPy, Joblib | High accuracy, fast sub-millisecond inference, lightweight `.pkl` models. |
| **Database** | SQLite via SQLAlchemy ORM | Zero-setup, serverless, self-contained, easily migratable to PostgreSQL in production. |
| **Security** | Bleach, Flask-Bcrypt, PyJWT, Flask-Limiter | Enterprise-grade security preventing XSS, SQL Injection, brute force, and credential leaks. |
| **Cloud Deployment** | Render (Backend) + Vercel (Frontend) | Free, production-ready, automatic SSL/HTTPS, zero server maintenance. |

---

## 4. Key Highlights for Project Evaluation
1. **Clean Code Separation**: Dedicated `frontend/`, `backend/`, `docs/`, and `tests/` folders.
2. **100% Test Coverage**: 51 automated unit and integration tests written in `pytest`.
3. **Responsive UI**: Interactive radar scanner animation, real-time risk gauges, copy-to-clipboard buttons, and toast notifications.
4. **Zero-Day Detection**: Detects brand-new malicious links that have never been reported to blacklists before.
