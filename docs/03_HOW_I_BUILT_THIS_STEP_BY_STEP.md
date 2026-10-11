# 🛠️ How I Built This Project — Step-by-Step Development Procedure

> **Guide for Students to Present to Teachers:**  
> Use this document when your teacher asks: *"How did you make this project? What was your step-by-step development process?"*  
> Walk them through these 8 clear stages in order.

---

### Stage 1: Problem Identification & Requirements Gathering
* **What I Did:** I researched recent cybersecurity reports from CERT-In and APWG (Anti-Phishing Working Group). I found that 85% of corporate cyber breaches start with a phishing email or deceptive link.
* **Objective Defined:** Create an all-in-one web tool that can accept either a link (URL) or an email text and classify it as Safe, Suspicious, or Phishing in under 2 seconds.

---

### Stage 2: System & Folder Architecture Design
To maintain professional software engineering standards, I divided the project into four clean, isolated modules:
```
phishing_email_url_generator/
├── backend/          # Python Flask REST API & ML Models
├── frontend/         # HTML5, Modern CSS Glassmorphism, JavaScript
├── docs/             # Documentation, viva questions, setup guides
├── tests/            # Automated Pytest unit & integration tests
├── requirements.txt  # Python dependencies with pinned versions
└── render.yaml       # Infrastructure as Code deployment specification
```

---

### Stage 3: Dataset Engineering & Machine Learning Training
1. **Synthetic & Real-World Feature Engineering (`train_model.py`)**:
   * I wrote feature extraction functions to convert raw URLs into an 8-dimensional numerical vector (dots, hyphens, length, IP presence, slash counts, digits ratio, etc.).
   * For emails, I built a balanced corpus of phishing emails (fake bank notices, lottery scams, password expiration warnings) and legitimate business emails.
2. **Model Training**:
   * **URL Model:** Trained a **RandomForestClassifier** with 100 estimators.
   * **Email Model:** Built a Scikit-Learn **Pipeline** combining `TfidfVectorizer` (sublinear TF scaling, n-grams 1-2) with `LogisticRegression`.
3. **Serialization:** Exported the trained models as `url_model.pkl` and `email_model.pkl` using `joblib` so they load into RAM instantly during server startup.

---

### Stage 4: Backend REST API & Database Development
1. **Framework Selection:** Built with **Python Flask 3.0** for its lightweight microservices architecture and seamless integration with Python ML packages.
2. **Database Schema (`database.py`)**:
   * Used **SQLAlchemy ORM** with SQLite.
   * Created two relational models: `User` (stores username, email, hashed password) and `ScanHistory` (stores target link, risk score, verdict, timestamp, foreign key to user).
3. **API Endpoints (`server.py`)**:
   * `/api/scan/url` & `/api/scan/email` (POST) — Scans input and computes risk score.
   * `/api/auth/register` & `/api/auth/login` (POST) — User registration and login.
   * `/api/history` & `/api/history/stats` (GET) — Paginated user scan history.
   * `/api/health` (GET) — System health monitoring.

---

### Stage 5: Enterprise-Grade Security Hardening
I ensured the application satisfies standard **OWASP Top 10** security practices:
* **XSS Defense:** Filtered every input through `bleach.clean()` to neutralize any `<script>` tags or malicious HTML payloads.
* **SQL Injection Defense:** All database queries strictly use SQLAlchemy ORM parameterized queries; raw SQL concatenation is completely banned.
* **Password Hashing:** Passwords are never stored in plain text. Used `flask-bcrypt` with salted Blowfish hashing (work factor 12).
* **Stateless Auth:** Implemented **JWT (JSON Web Tokens)** with SHA-256 signatures and automatic expiration.
* **Rate Limiting:** Added `Flask-Limiter` with client IP tracking (e.g. 10 scans/minute) to prevent Denial-of-Service (DoS) and API abuse.

---

### Stage 6: Modern UI/UX Frontend Design
1. **Design System:** Developed a dark glassmorphic design system using Vanilla CSS3 custom properties (CSS variables), backdrop blur filters, and subtle ambient glows.
2. **Interactive Elements:**
   * Custom CSS **Radar Scanner Animation** that pulses during active scans.
   * Dynamic **Risk Gauge Bar** (color changes from emerald green to amber to crimson red).
   * **Custom Toast Notification System (`toast.js`)** providing real-time non-blocking alerts.
   * Password strength meter showing complexity in real time during registration.
   * One-click "Copy Result" button and printable PDF/scan reports.

---

### Stage 7: Rigorous Automated Testing
* Configured `pytest` in `pytest.ini`.
* Wrote **51 automated test cases** across:
  * `tests/test_api.py` (24 integration tests covering all HTTP routes, authentication flows, rate limits, and error codes).
  * `tests/test_utils.py` (27 unit tests verifying sanitization, heuristic calculations, URL validators, and verdict scoring).
* Achieved **100% test pass rate** with 0 warnings.

---

### Stage 8: Production Deployment Setup
* **Backend:** Configured for **Render** using a production WSGI server (`gunicorn`), `Procfile`, and `render.yaml` infrastructure-as-code.
* **Frontend:** Configured for **Vercel** with `vercel.json` routing, security headers, and dynamic API base URL resolution.
