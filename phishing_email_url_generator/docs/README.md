# 📚 PhishGuard Documentation Index

Welcome to the comprehensive documentation suite for **PhishGuard**. These guides are designed in simple, clear language to help you explain every technical aspect to teachers, project evaluators, and viva examiners.

---

## 📑 Guides Included:

| Document | Description | Best For |
|---|---|---|
| [**01. Project Overview**](./01_PROJECT_OVERVIEW.md) | High-level summary, architecture diagram, problem statement & tech stack. | Introducing the project in your presentation slides. |
| [**02. How It Works (Simplified)**](./02_HOW_IT_WORKS_EXPLAINED_SIMPLY.md) | The 3-tier hybrid engine, scoring formula, algorithms, and airport security analogy. | Explaining the logic to non-technical and technical professors. |
| [**03. Step-by-Step Development Procedure**](./03_HOW_I_BUILT_THIS_STEP_BY_STEP.md) | The 8-phase developmental lifecycle from research to deployment. | Answering *"How did you build this step-by-step from scratch?"* |
| [**04. Teacher Viva Q&A Cheat Sheet**](./04_TEACHER_VIVA_QUESTIONS_AND_ANSWERS.md) | 25+ real exam questions on ML, XSS, SQLi, Bcrypt, JWT, and homoglyphs. | Preparing for oral viva defense and teacher questions. |
| [**05. REST API Documentation**](./05_API_DOCUMENTATION.md) | Complete endpoints reference, request payloads, response JSONs, and HTTP codes. | Explaining backend architecture and client-server communication. |
| [**06. Local Setup & Running Guide**](./06_LOCAL_SETUP_AND_RUN_GUIDE.md) | Step-by-step commands to install, train models, run servers, and execute tests. | Running a live demo in the college lab or on your laptop. |
| [**07. Cloud Deployment Guide (Render & Vercel)**](./07_DEPLOYMENT_GUIDE_RENDER_AND_VERCEL.md) | Step-by-step instructions to deploy backend on Render and frontend on Vercel. | Showing your project live on the internet via mobile or college PC. |

---

## 🧭 Project Directory Structure:
```
phishing_email_url_generator/
├── backend/                  # Python Flask REST API, ML Models & SQLite DB
│   ├── auth.py               # User authentication (register, login, JWT)
│   ├── database.py           # SQLAlchemy User & ScanHistory models
│   ├── email_model.pkl       # Trained TF-IDF + LogisticRegression model
│   ├── scanner.py            # Hybrid detection engine & Threat Intel APIs
│   ├── server.py             # Flask application entry point & CORS
│   ├── train_model.py        # ML training script
│   ├── url_model.pkl         # Trained RandomForestClassifier model
│   ├── utils.py              # Sanitization, validators & heuristic rules
│   ├── Procfile              # Render WSGI runner
│   └── requirements.txt      # Backend Python dependencies
│
├── frontend/                 # Pure HTML5, Vanilla CSS3 & Modern JavaScript
│   ├── assets/
│   │   ├── css/style.css     # Dark glassmorphic design system
│   │   └── js/
│   │       ├── api.js        # Dynamic API client & JWT interceptor
│   │       ├── app.js        # UI logic, radar animation & tabs
│   │       └── toast.js      # Toast notification system
│   ├── auth.html             # Login & Registration page
│   ├── dashboard.html        # Scan history & user stats page
│   ├── index.html            # Main scanner page
│   └── vercel.json           # Vercel frontend routing configuration
│
├── docs/                     # Full teacher documentation & viva guides
│   ├── 01_PROJECT_OVERVIEW.md
│   ├── 02_HOW_IT_WORKS_EXPLAINED_SIMPLY.md
│   ├── 03_HOW_I_BUILT_THIS_STEP_BY_STEP.md
│   ├── 04_TEACHER_VIVA_QUESTIONS_AND_ANSWERS.md
│   ├── 05_API_DOCUMENTATION.md
│   ├── 06_LOCAL_SETUP_AND_RUN_GUIDE.md
│   ├── 07_DEPLOYMENT_GUIDE_RENDER_AND_VERCEL.md
│   └── README.md
│
├── tests/                    # Automated testing suite (pytest)
│   ├── __init__.py
│   ├── test_api.py           # 24 API integration tests
│   └── test_utils.py         # 27 unit tests (heuristics & validators)
│
├── .env.example              # Template for environment secrets
├── .gitignore                # Git repository hygiene filter
├── Procfile                  # Root Render runner
├── pytest.ini                # Pytest configuration
├── render.yaml               # Render Infrastructure-as-Code blueprint
├── requirements.txt          # Python dependencies
├── start_server.ps1          # One-click Windows PowerShell starter
├── train_model.py            # Root ML model trainer
└── vercel.json               # Root Vercel routing configuration
```
