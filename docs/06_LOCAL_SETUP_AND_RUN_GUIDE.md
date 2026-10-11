# 💻 Local Setup & Running Guide (Windows, Mac & Linux)

Follow these exact steps to run the complete PhishGuard system locally on your laptop or computer.

---

## Prerequisites
* **Python 3.10+** (Python 3.11, 3.12, or 3.13)
* Any modern web browser (Google Chrome, Brave, Firefox, Edge)

---

## Step 1: Open Terminal & Navigate to Project
```powershell
cd "d:\BCA Material\phishing_email_url_generator"
```

---

## Step 2: Install Required Dependencies
```powershell
pip install -r requirements.txt
```

---

## Step 3: Train the Machine Learning Models (One-time)
```powershell
python train_model.py
```
*Output:*
```
[INFO] Training URL RandomForestClassifier...
[INFO] Model saved to backend/url_model.pkl
[INFO] Training Email TF-IDF + LogisticRegression pipeline...
[INFO] Model saved to backend/email_model.pkl
```

---

## Step 4: Start the Backend API Server
Open **Terminal 1**:
```powershell
python backend/server.py
```
*The API will start listening on:* `http://127.0.0.1:5000`

---

## Step 5: Start the Frontend Static Web Server
Open **Terminal 2**:
```powershell
python -m http.server 3000 --directory frontend
```
*The Web App will be live at:* `http://localhost:3000`

> 🚀 **Quick Windows Shortcut:** You can also simply right-click and run `start_server.ps1` in PowerShell to launch both automatically!

---

## Step 6: Run Automated Tests
Open **Terminal 3**:
```powershell
pytest
```
*Expected Output:*
```
============================= 51 passed in 10s =============================
```

---

## Step 7: How to Give a 2-Minute Demo to Teachers
1. Open your browser to `http://localhost:3000`.
2. **Demo URL Scan (Safe):** Paste `https://www.google.com` $\rightarrow$ Click **Analyze URL**.  
   *Watch the Radar scanner run and display a green SAFE badge (Score: ~5/100).*
3. **Demo URL Scan (Phishing):** Paste `http://192.168.1.50/paypal-update-account/login.php` $\rightarrow$ Click **Analyze URL**.  
   *The radar turns red, showing PHISHING (Score: 85+/100) with detailed heuristic flags!*
4. **Demo Email Scan:** Switch to the **Email Content tab**, paste:  
   *"URGENT: Your account has been compromised. Verify your bank password immediately."*  
   *Click **Analyze Email** $\rightarrow$ Show high-risk phishing verdict.*
5. **Demo Auth & History:** Click **Sign In** in the top navigation, log in, and view the **Scan History & Stats Dashboard**!
