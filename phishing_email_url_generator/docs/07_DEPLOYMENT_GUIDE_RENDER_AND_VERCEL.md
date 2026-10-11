# 🚀 Cloud Deployment Guide — Render (Backend) & Vercel (Frontend)

This guide walks you through deploying PhishGuard to the cloud for free with **100% working live URLs** that you can show your teachers and examiners.

```
+------------------------------------+        HTTPS REST API        +------------------------------------+
|         VERCEL (Frontend)          | ---------------------------> |          RENDER (Backend)          |
|  https://phishguard.vercel.app     | <--------------------------- |  https://phishguard.onrender.com   |
|  • HTML5 + CSS3 Glassmorphism UI   |        JSON Responses        |  • Flask + Gunicorn WSGI Server    |
|  • Instant Global Edge CDN         |                              |  • Scikit-Learn ML Models (.pkl)   |
+------------------------------------+                              +------------------------------------+
```

---

## Part 1: Deploy Backend to Render (Free Tier)

### Step 1: Push Code to GitHub
Ensure your latest code is pushed to your GitHub repository:
```bash
git add .
git commit -m "Configure PhishGuard for Render and Vercel deployment"
git push origin main
```

### Step 2: Create Web Service on Render
1. Go to [https://render.com](https://render.com) and sign in with GitHub.
2. Click **New +** $\rightarrow$ **Web Service**.
3. Select your GitHub repository (`phishing_email_url_generator`).
4. Configure the settings:
   * **Name:** `phishguard-backend` *(or any unique name)*
   * **Region:** Any (e.g. *Oregon, USA* or *Frankfurt, EU*)
   * **Branch:** `main`
   * **Root Directory:** *(leave blank)*
   * **Runtime:** `Python 3`
   * **Build Command:**  
     ```bash
     pip install -r requirements.txt && python train_model.py
     ```
   * **Start Command:**  
     ```bash
     gunicorn --chdir backend "server:app" --workers 2 --bind 0.0.0.0:$PORT
     ```
   * **Instance Type:** `Free`

### Step 3: Add Environment Variables in Render Dashboard
Scroll to the **Environment Variables** section and add:
| Key | Value | Notes |
|---|---|---|
| `PYTHON_VERSION` | `3.11.9` | Pre-compiled wheel stability |
| `SECRET_KEY` | *(Click "Generate")* | Flask session secret |
| `JWT_SECRET_KEY` | *(Click "Generate")* | Token signing secret |
| `CORS_ORIGINS` | `*` | Allows your Vercel frontend domain |
| `FLASK_DEBUG` | `0` | Production mode |

### Step 4: Deploy & Verify
1. Click **Deploy Web Service**.
2. Wait 2–3 minutes for build to complete.
3. Once live, Render gives you a URL like: `https://phishguard-backend.onrender.com`.
4. Test it in your browser: open `https://phishguard-backend.onrender.com/api/health`.  
   *You should see:* `{"status":"ok","version":"1.0.0"}`.

> ⚠️ **Important Note on Render Free Tier:** Render puts free instances to sleep after 15 minutes of inactivity. When you open the app after a while, the very first request takes ~30 seconds to wake up the server.

---

## Part 2: Deploy Frontend to Vercel (Free Tier)

### Step 1: Import Project into Vercel
1. Go to [https://vercel.com](https://vercel.com) and sign in with GitHub.
2. Click **Add New...** $\rightarrow$ **Project**.
3. Select your GitHub repository.

### Step 2: Configure Project Settings
* **Framework Preset:** `Other`
* **Root Directory:** Click "Edit" and choose `frontend` *(or leave as root, our `vercel.json` supports both!)*.
* Leave Build Command and Output Directory as default.

### Step 3: Deploy!
1. Click **Deploy**.
2. Within 15 seconds, Vercel deploys your frontend and gives you a live URL like:  
   `https://phishguard-yourusername.vercel.app`!

---

## Part 3: Connect Frontend to Your Live Render Backend

Our frontend `api.js` has a **built-in dynamic URL resolver**. You have three easy ways to point your frontend to your new Render backend:

### Option A: Direct in Code (Recommended before pushing)
In [frontend/assets/js/api.js](file:///d:/BCA%20Material/phishing_email_url_generator/frontend/assets/js/api.js), update line 22:
```javascript
return 'https://YOUR-ACTUAL-RENDER-NAME.onrender.com';
```
Commit and push. Vercel will auto-redeploy in 10 seconds!

### Option B: Runtime Browser Configuration (Zero Re-deployment)
If you already deployed on Vercel and want to switch backend URLs on the fly:
1. Open your live Vercel site in Chrome.
2. Open Developer Tools (`F12` $\rightarrow$ Console).
3. Type:
   ```javascript
   Api.setApiBase('https://YOUR-RENDER-NAME.onrender.com');
   ```
4. Press Enter and refresh the page. The app will permanently use this backend!

---

## Part 4: Final Testing Checklist for Teachers
- [x] Backend responds to `GET /api/health` with `{"status": "ok"}`
- [x] Frontend loads on HTTPS with dark glassmorphism styling
- [x] URL Scan works and displays animated radar + score
- [x] Email Scan works with NLP urgency detection
- [x] Sign In & Registration works and saves tokens to LocalStorage
- [x] History page displays past scans saved in the cloud database
