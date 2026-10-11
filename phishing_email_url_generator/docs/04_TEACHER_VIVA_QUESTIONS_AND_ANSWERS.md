# 🎓 Teacher Viva Questions & Answers (Master Cheat Sheet)

> **Instructions for the Student:**  
> Review these questions before your presentation or viva exam. Practice answering in the simple, confident language provided below.

---

### Q1: "What is the primary objective of your project?"
**Answer:**  
*"Sir/Ma'am, PhishGuard is an intelligent cybersecurity web application designed to detect phishing links and fraudulent emails in real time. It uses a 3-layer hybrid detection engine combining Machine Learning, Heuristic Rules, and Threat Intelligence APIs to achieve high accuracy and catch both known and brand-new zero-day threats."*

---

### Q2: "Why did you use a Hybrid Approach instead of just Machine Learning?"
**Answer:**  
*"Pure Machine Learning can suffer from false negatives or edge-case manipulation (e.g. an attacker modifying a few letters). On the other hand, static rule-based systems cannot detect new, evolving threats. By combining Machine Learning (40%), Heuristics (40%), and Threat Intelligence (20%), each layer covers the weaknesses of the others, giving a balanced and robust risk score."*

---

### Q3: "Which Machine Learning algorithms did you use and why?"
**Answer:**  
*"I used two models:*  
*1. **Random Forest Classifier for URLs:** Random Forest builds multiple decision trees and merges their votes. It handles non-linear numerical features (like dot count, length, and hyphen count) extremely well without overfitting.*  
*2. **TF-IDF + Logistic Regression for Emails:** Natural language text requires vectorization. TF-IDF gives high mathematical weights to suspicious psychological trigger words while downweighting common English words, and Logistic Regression outputs a calibrated probability between 0 and 1."*

---

### Q4: "How does your URL feature extraction work?"
**Answer:**  
*"When a user inputs a URL, the system extracts 8 structural features before sending them to the model:*  
*1. Total URL length*  
*2. Number of dots (subdomains)*  
*3. Whether an IP address is used instead of a domain name*  
*4. Presence of an `@` symbol (URL redirection trick)*  
*5. Double slash count `//`*  
*6. Number of hyphens (often used to fake real brand names)*  
*7. Ratio of digits to total characters*  
*8. Presence of suspicious keywords like `login`, `bank`, or `verify`."*

---

### Q5: "What is a Homoglyph Attack and how does your application detect it?"
**Answer:**  
*"A Homoglyph attack (also called an IDN homograph attack) occurs when an attacker registers a domain using characters from other alphabets—like Cyrillic or Greek—that look identical to Latin letters. For example, replacing the Latin letter 'o' with the Cyrillic 'о'. In the browser, this domain is represented as Punycode starting with `xn--`. My heuristic engine immediately checks for `xn--` and flags any punycode domain with an elevated risk score."*

---

### Q6: "How do you protect your application against SQL Injection?"
**Answer:**  
*"I used **SQLAlchemy ORM**, which automatically uses parameterized queries and prepared statements. User inputs are treated strictly as data, never as executable SQL statements, preventing SQL injection completely."*

---

### Q7: "How do you protect your application against Cross-Site Scripting (XSS)?"
**Answer:**  
*"Every input string received by the backend is sanitized using Python's `bleach` library (`bleach.clean(strip=True)`). This strips out any HTML tags, `<script>` payloads, or malicious javascript before the input is processed or stored in the database."*

---

### Q8: "How are user passwords stored in the database?"
**Answer:**  
*"Passwords are **never** stored in plain text. I used **Bcrypt** (`flask-bcrypt`) with salted Blowfish encryption. Even if someone obtains read access to the database, they cannot reverse the hashes back into the original passwords."*

---

### Q9: "Why did you use JWT (JSON Web Tokens) instead of traditional server sessions?"
**Answer:**  
*"JWTs are stateless and self-contained. The server does not need to store session IDs in server memory, making the application scalable across distributed cloud servers (like Render). Each request carries the signed token in the `Authorization: Bearer <token>` header."*

---

### Q10: "How does your system prevent Denial of Service (DoS) attacks?"
**Answer:**  
*"I implemented IP-based rate limiting using **Flask-Limiter**. For example, a single IP address is restricted to a maximum of 10 scans per minute. If a script tries to spam the server, it receives an HTTP 429 'Too Many Requests' response."*

---

### Q11: "What database did you use and how can it scale?"
**Answer:**  
*"In development, I used **SQLite** via SQLAlchemy because it requires zero configuration and stores data cleanly in a local file. In production on Render, the code is already configured to automatically switch to **PostgreSQL** by simply setting the `DATABASE_URL` environment variable."*

---

### Q12: "How did you test your project?"
**Answer:**  
*"I wrote a comprehensive test suite using **pytest** containing **51 automated test cases**:*  
*• 24 API integration tests in `tests/test_api.py` (testing login, registration, scans, headers, and 404/429 errors).*  
*• 27 unit tests in `tests/test_utils.py` (testing sanitization, URL validation, and heuristic math).*  
*All 51 tests pass with 100% success."*

---

### Q13: "What are the three final verdicts and what do they mean?"
**Answer:**  
*"Based on the 0 to 100 Risk Score:*  
*• **SAFE (0 — 39):** Green badge. Normal structure, no red flags.*  
*• **SUSPICIOUS (40 — 69):** Amber badge. Contains multiple warnings like shortened URLs or urgency language.*  
*• **PHISHING (70 — 100):** Red badge. High probability of malicious intent. User is warned not to open."*

---

### Q14: "Why did you choose to deploy Frontend on Vercel and Backend on Render?"
**Answer:**  
*"This follows modern decoupled cloud architecture:*  
*• **Vercel** is globally optimized with edge CDN networks for static frontend assets (HTML, CSS, JS).*  
*• **Render** is an excellent cloud platform for containerized Python WSGI backend services running `gunicorn`.*  
*This separation allows each layer to scale independently without affecting the other."*
