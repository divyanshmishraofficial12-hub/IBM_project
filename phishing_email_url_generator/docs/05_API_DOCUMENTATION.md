# 📡 REST API Reference Documentation

This document describes all API endpoints provided by the PhishGuard Flask backend service.

---

## 1. Overview
* **Base URL (Local):** `http://127.0.0.1:5000`
* **Base URL (Production):** `https://YOUR-RENDER-APP.onrender.com`
* **Content-Type:** `application/json`
* **Authentication:** Pass JWT token in `Authorization: Bearer <token>` header for protected endpoints.

---

## 2. Endpoints Summary Table

| Method | Endpoint | Description | Auth Required? | Rate Limit |
|---|---|---|---|---|
| `GET` | `/` | Root service health & info | No | None |
| `GET` | `/api/health` | Service healthcheck & version | No | None |
| `POST` | `/api/auth/register` | Register a new user | No | 20 / min |
| `POST` | `/api/auth/login` | Log in and receive JWT token | No | 20 / min |
| `GET` | `/api/auth/me` | Fetch authenticated user profile | **Yes** (Bearer) | None |
| `POST` | `/api/scan/url` | Scan URL for phishing indicators | Optional | 10 / min |
| `POST` | `/api/scan/email` | Scan email text for phishing | Optional | 10 / min |
| `GET` | `/api/history` | Paginated scan history for user | **Yes** (Bearer) | None |
| `GET` | `/api/history/stats` | Aggregated user scan statistics | **Yes** (Bearer) | None |
| `DELETE` | `/api/history/<id>` | Delete a single scan record | **Yes** (Bearer) | None |
| `DELETE` | `/api/history` | **Bulk delete** all scan records | **Yes** (Bearer) | None |

---

## 3. Detailed Request & Response Examples

### A. Scan URL
* **Route:** `POST /api/scan/url`
* **Headers:** `Content-Type: application/json`, *(Optional)* `Authorization: Bearer <token>`
* **Request Body:**
```json
{
  "url": "http://192.168.1.1/paypal-update-account/verify.php"
}
```
* **Success Response (`200 OK`):**
```json
{
  "target": "http://192.168.1.1/paypal-update-account/verify.php",
  "scan_type": "url",
  "risk_score": 0.885,
  "verdict": "phishing",
  "ml_score": 0.92,
  "heuristic_score": 0.85,
  "gsb_flagged": false,
  "vt_positives": 0,
  "details": {
    "ml_available": true,
    "gsb_enabled": false,
    "vt_enabled": false
  },
  "scanned_at": "2026-09-13T14:30:00.000Z"
}
```

---

### B. Scan Email
* **Route:** `POST /api/scan/email`
* **Request Body:**
```json
{
  "email_text": "URGENT: Your bank account will be suspended within 24 hours. Click here to verify your credentials immediately."
}
```
* **Success Response (`200 OK`):**
```json
{
  "target": "URGENT: Your bank account will be suspended...",
  "scan_type": "email",
  "risk_score": 82.0,
  "verdict": "PHISHING",
  "ml_score": 0.88,
  "heuristic_score": 0.76,
  "urgency_detected": true,
  "financial_detected": true,
  "scanned_at": "2026-09-13T14:30:00Z"
}
```

---

### C. Register User
* **Route:** `POST /api/auth/register`
* **Request Body:**
```json
{
  "username": "student123",
  "email": "student@college.edu",
  "password": "SecurePassword123!"
}
```
* **Success Response (`201 Created`):**
```json
{
  "message": "User registered successfully.",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6...",
  "user": {
    "id": 1,
    "username": "student123",
    "email": "student@college.edu"
  }
}
```

---

### D. User Scan History Stats
* **Route:** `GET /api/history/stats`
* **Headers:** `Authorization: Bearer <token>`
* **Success Response (`200 OK`):**
```json
{
  "stats": {
    "safe": 12,
    "suspicious": 5,
    "phishing": 8
  },
  "total": 25
}
```

---

### E. Bulk Delete All History
* **Route:** `DELETE /api/history`
* **Headers:** `Authorization: Bearer <token>`
* **Success Response (`200 OK`):**
```json
{
  "message": "Deleted 25 records.",
  "deleted": 25
}
```
* **Error Response (`401 Unauthorized`):** Missing or invalid token.
