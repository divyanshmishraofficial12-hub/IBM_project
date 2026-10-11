# 🛡️ PhishGuard Forensics — Citizen Cyber Shield & Threat Intelligence

[![Python](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0.3-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Tests](https://img.shields.io/badge/Tests-58%2F58%20Passed-2ea44f?logo=pytest&logoColor=white)](./tests)
[![Vercel](https://img.shields.io/badge/Frontend-Vercel%20Ready-black?logo=vercel&logoColor=white)](https://vercel.com)
[![Render](https://img.shields.io/badge/Backend-Render%20Ready-46E3B7?logo=render&logoColor=white)](https://render.com)

> Next-Generation AI Threat Defense & Digital Forensics workbench designed to protect everyday citizens and enterprise SOCs against zero-day URLs, WhatsApp scams, UPI payment traps, and Quishing.

---

## 🏆 What Makes This Project A Competition Winner?

Unlike basic student projects that only count dots or fail on malformed links like `https://gjgku`:

- 🧪 **Shannon Entropy & DGA Engine**: Calculates mathematical character disorder to catch algorithmic malware domains and invalid gibberish links instantly.
- 📱 **WhatsApp & SMS Scam Triage**: Detects everyday social engineering attacks (Electricity bill cutoff, Bank KYC freeze, YouTube task jobs, Fake Police "Digital Arrest").
- 💳 **UPI & QR Fraud Shield (Quishing)**: Audits QR codes and deep-links (`upi://pay?pa=...`) to warn citizens: *"DANGER: This QR code will DEDUCT money, NOT receive money!"*
- 🛡️ **MITRE ATT&CK Enterprise Matrix**: Automatically maps threats to `T1566.002`, `T1568.002`, and `T1583.001`.
- 🖨️ **1-Click Forensic Case Report**: Exports audit-ready incident reports with cryptographic SHA-256 evidence hashing for law enforcement or bank disputes.
- 🚨 **Direct 1930 Integration**: Provides one-click access to the National Cyber Crime Helpline and Sanchar Saathi portal.

---

## 🚀 Live Demo & Local Quickstart

### 1. Clone & Setup
```bash
git clone https://github.com/YOUR-USERNAME/phishguard.git
cd phishguard
copy .env.example .env
pip install -r requirements.txt
```

### 2. Start Backend API (Port 5000)
```bash
python backend/server.py
```

### 3. Launch Frontend Web App (Port 3000)
```bash
python -m http.server 3000 --directory frontend
```
Open **[http://localhost:3000](http://localhost:3000)** in your browser.

---

## 🧪 Testing

Run the full automated test suite (58 unit & integration tests):
```bash
pytest tests/ -v
```

---

## 📁 System Architecture

```
├── backend/
│   ├── server.py        # Flask REST API (CORS, Limiter, JWT auth, routes)
│   ├── scanner.py       # ML inference, XAI, MITRE ATT&CK, SHA-256 hashing
│   ├── utils.py         # Shannon entropy, DGA detector, UPI parser, TLD validator
│   ├── train_model.py   # 22-feature RandomForest & TF-IDF model pipeline
│   ├── auth.py          # User registration & JWT authentication
│   └── database.py      # SQLAlchemy models & SQLite store
├── frontend/
│   ├── index.html       # 4-Vector Scanner Studio & XAI Report Dashboard
│   ├── dashboard.html   # Personal scan history & metrics
│   ├── auth.html        # Login & registration portal
│   └── assets/          # CSS design system, API client, & Toast engine
└── tests/
    ├── test_api.py      # Integration tests (URLs, DGA, SMS scams, UPI QR, unshortener)
    └── test_utils.py    # Unit tests for core algorithms
```

---

## 📄 License
MIT License · Built for educational & cybersecurity defense innovation.
