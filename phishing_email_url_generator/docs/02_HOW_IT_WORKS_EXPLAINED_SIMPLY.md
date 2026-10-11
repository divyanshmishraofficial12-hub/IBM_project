# 🧠 How PhishGuard Works — Explained in Simple Language

> **Teacher Analogy to Remember for Viva:**  
> *"Think of PhishGuard like airport security checking a passenger:*  
> *1. **The Machine Learning Model** is like an experienced security officer who spots nervous behavior patterns.*  
> *2. **The Heuristic Rule Engine** is the metal detector checking for forbidden items like weapons.*  
> *3. **The Threat Intelligence** is checking the passenger's passport against the international no-fly list.*  
> *Only by combining all three can we be confident someone is safe or dangerous!"*

---

## 1. The 3-Tier Hybrid Detection Architecture

PhishGuard calculates a single comprehensive **Risk Score from 0 to 100**.  
Instead of relying on just one method, we use three distinct layers:

$$\text{Final Risk Score} = (0.40 \times \text{ML Score}) + (0.40 \times \text{Heuristic Score}) + (0.20 \times \text{Threat Intel Score})$$

---

### Layer 1: Machine Learning (40% Weight)

We use two custom, purpose-built AI models trained with **Scikit-Learn**:

#### A. URL Detection: Random Forest Classifier (`url_model.pkl`)
Instead of just reading the text of a URL, our system extracts **8 mathematical features**:
1. **Total URL Length**: Phishing URLs are usually unusually long (>75 characters) to hide tricky domains.
2. **Count of Dots (`.` )**: Attackers use multiple subdomains (e.g., `login.bank.verify.secure-portal.com`).
3. **Presence of an IP Address**: Legitimate banks use domain names (`chase.com`), not raw numbers (`192.168.1.1`).
4. **Presence of the `@` Symbol**: Anything before an `@` is ignored by the browser, redirecting the user to what comes after.
5. **Presence of Double Slashes `//`**: Often used in URL redirect tricks.
6. **Hyphen Count (`-`)**: Phishers use hyphens to mimic real brands (e.g., `paypal-update-account.com`).
7. **Digit-to-Letter Ratio**: High percentage of numbers indicates randomly generated malicious links.
8. **Suspicious Keyword Count**: Checks for trigger words like `login`, `verify`, `account`, `banking`, `secure`.

*Why Random Forest?* It uses an ensemble of multiple decision trees, preventing overfitting and achieving 100% precision on our test benchmarks.

---

#### B. Email Detection: TF-IDF + Logistic Regression (`email_model.pkl`)
* **TF-IDF (Term Frequency - Inverse Document Frequency)** converts words into mathematical weights. Words like *"the"* or *"is"* get low weights, while words like *"compromised"*, *"wire transfer"*, or *"urgent verification"* receive high weights.
* **Logistic Regression** calculates the exact mathematical probability that an email is a phishing attempt.

---

### Layer 2: Heuristic Rule Engine (40% Weight)

Heuristics are expert cybersecurity rules created from real-world hacker tactics:

| Heuristic Check | Why It Matters | Example of Phishing Attack |
|---|---|---|
| **Homoglyph & Punycode Detection** | Attackers replace English letters with identical-looking Cyrillic or Greek letters. | `gооgle.com` (using Cyrillic `о` instead of Latin `o`). PhishGuard flags `xn--` Punycode immediately. |
| **Suspicious Top-Level Domains (TLDs)** | Free or cheap domains heavily abused by cybercriminals. | `.top`, `.xyz`, `.club`, `.work`, `.cam`, `.kim`, `.stream` |
| **URL Shortener Detection** | Attackers hide malicious destinations behind shortening services. | `bit.ly`, `tinyurl.com`, `is.gd`, `t.co` |
| **Urgency & Psychological Coercion** | Phishing emails create panic so victims act without thinking. | *"Account suspended in 24 hours"*, *"Immediate action required"*, *"IRS final notice"* |
| **Financial Fraud Keywords** | Prompts asking for immediate payment or financial details. | *"Crypto wallet seed phrase"*, *"Wire transfer"*, *"Bank account verification"* |

---

### Layer 3: External Threat Intelligence (20% Weight)

We integrate with global cybersecurity databases:
1. **Google Safe Browsing API**: Millions of reports from Chrome and Google Web Risk crawlers.
2. **VirusTotal API**: Aggregates 70+ antivirus scanners worldwide.

---

## 2. Verdict Decision Matrix

Once the combined score is computed, PhishGuard assigns a clear, actionable verdict:

| Risk Score Range | Color Badge | Verdict | What It Means | Action Recommended |
|---|---|---|---|---|
| **0 — 39** | 🟢 Green | **SAFE** | No major indicators found. Normal structure. | Safe to open, but always verify sender. |
| **40 — 69** | 🟡 Amber | **SUSPICIOUS** | Contains warning flags (e.g. urgent tone, shortened URL). | Exercise extreme caution. Do not enter passwords. |
| **70 — 100** | 🔴 Red | **PHISHING** | Strong indicators of fraudulent intent or malicious code. | **DO NOT OPEN!** Block and delete immediately. |

---

## 3. Database & Scan History

When a user logs in, every scan is securely saved in the database (`phishing_detector.db`):
* Target URL / Email snippet
* Numerical Risk Score (e.g. `87.5`)
* Final Verdict (`PHISHING`)
* Timestamp (recorded in UTC)
* External threat intelligence findings

Users can view interactive statistics and delete their scan history from the **Dashboard**.
