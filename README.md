# MailShield – Email Spam & Phishing Detection System

**Academic Final-Year Project: Design and Implementation of an Email Spam and Phishing Detection System**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Flask 3.0+](https://img.shields.io/badge/Framework-Flask%203.0%2B-black.svg)](https://flask.palletsprojects.com/)
[![License: Academic / Defensive](https://img.shields.io/badge/License-Academic%20Defensive-green.svg)](#)
[![Tests: 28 Passed](https://img.shields.io/badge/Tests-28%20Passed-brightgreen.svg)](#)

---

## 📌 Executive Summary

**MailShield** is a defensive cybersecurity and threat intelligence web platform designed to analyze, detect, and explain malicious email threats. Unlike conventional filters that output opaque verdicts or rely solely on basic blacklists, MailShield deploys a **Hybrid Multi-Vector Decision Engine** integrating:

1. **Natural Language Processing & Machine Learning**: TF-IDF unigram/bigram tokenization + calibrated Multinomial Naive Bayes classification.
2. **Deterministic Phishing Linguistic Heuristics**: Multi-category weighted scoring for urgency, credential harvesting, financial fraud, and security simulation cues.
3. **Static Lexical URL Decomposition**: Inspection of IP hosts, suspicious TLDs, URL shorteners, Punycode homographs, excessive subdomain depth, and brand impersonation without making dangerous external connections.
4. **Sender Identity Verification**: Detection of display-name brand spoofing, From vs Reply-To mismatches, and lookalike/typosquatted domains.
5. **Transport Header Analysis**: Parsing and verification of RFC standard SPF, DKIM, and DMARC authentication verdicts.
6. **Attachment Metadata Inspection**: Identification of high-risk executables, scripts, macro-enabled documents, and deceptive double extensions.
7. **Explainable AI Diagnostics**: Dynamic generation of evidence-backed explanations, risk meters, and downloadable PDF security reports.

---

## 🛠️ Technology Stack

| Layer | Technologies Used |
| :--- | :--- |
| **Backend** | Python 3.11+, Flask 3, Werkzeug, python-dotenv, Flask-Login, Flask-SQLAlchemy |
| **Machine Learning & NLP** | scikit-learn, pandas, numpy, joblib, nltk, regex |
| **Email Parsing** | Python `email` library (RFC 822/2822 standard), BeautifulSoup4, urllib.parse |
| **Frontend & UI** | HTML5, CSS3, JavaScript (ES6+), Bootstrap 5, FontAwesome 6, Chart.js |
| **Database** | SQLite (Local Development) & PostgreSQL compatibility (Production) |
| **Reporting & Export** | ReportLab (Professional PDF Audit Reports) |
| **Testing & CI/CD** | pytest (Comprehensive automated test suite) |
| **WSGI Server** | Gunicorn (Production deployment) |

---

## 🚀 Quickstart & Local Installation

### 1. Prerequisites
- Python 3.11, 3.12, or 3.13 installed
- Git installed

### 2. Clone and Setup Environment

```bash
# Clone the repository
git clone <repository_url>
cd "email spam"

# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
# On Linux / macOS:
source venv/bin/activate
# On Windows (PowerShell):
# .\venv\Scripts\Activate.ps1

# Install required dependencies
pip install -r requirements.txt
```

### 3. Train the Machine Learning Model

Train and serialize the TF-IDF vectorizer and Naive Bayes classifier on the sample dataset:

```bash
python ml/train_model.py
```

*Output:*
- `models/spam_vectorizer.pkl`
- `models/spam_classifier.pkl`
- `models/evaluation_metrics.json`

### 4. Initialize Database and Seed Demo Scenarios

```bash
python seed_demo_data.py
```

*This creates the SQLite database (`instance/mailshield_dev.db`), sets up the default administrator account (`admin` / `Admin@12345`), and seeds 6 realistic educational scenarios.*

### 5. Run the Application

```bash
python app.py
```

Open your browser and navigate to: **`http://127.0.0.1:5000`**

---

## 🔑 Demonstration & Defense Credentials

| Account Role | Username | Email | Password |
| :--- | :--- | :--- | :--- |
| **System Administrator** | `admin` | `admin@mailshield.local` | `Admin@12345` |
| **Standard User** | *(Register any account via `/auth/register`)* | — | — |

---

## 🧪 Interactive Academic Defense Demo Mode

On the **Analyze Email** page (`/analyze`), click any of the **One-Click Academic Demo Presets**:

1. **Legitimate Meeting (Safe)**: Routine corporate sprint review with clean URLs.
2. **Lottery Sweepstakes (Spam)**: High promotional keyword density and get-rich-quick claims.
3. **Microsoft Office 365 (Phishing)**: Urgent credential harvesting with high-risk `.xyz` domain.
4. **PayPal Account Restriction (Phishing)**: Display name brand deception and IP address landing URL.
5. **Weaponized Attachment (Malicious)**: Deceptive double extension (`Invoice_Aug2026.pdf.exe`).
6. **Raw RFC 822 Email (MIME)**: Full raw message headers showing failed SPF/DKIM/DMARC verdicts.

---

## 🔬 Running Automated Tests

Run the complete test suite containing **28 automated test cases**:

```bash
pytest -v
```

### Test Coverage Areas:
- `tests/test_auth.py`: Registration, password hashing, validation, session lifecycle.
- `tests/test_parser.py`: RFC 822 MIME parsing, HTML extraction, malformed headers.
- `tests/test_urls.py`: Static URL lexical heuristics, IP hosts, Punycode, TLDs, shorteners.
- `tests/test_detector.py`: Urgency/credential NLP rules, sender spoofing, attachment threats.
- `tests/test_risk_engine.py`: Hybrid multi-vector synthesis, classifications, risk escalation.
- `tests/test_routes.py`: Web dashboard, analysis workflows, PDF report generation, REST API.

---

## 🌐 REST API Endpoints

MailShield provides REST API endpoints for integration with external email clients, security automation pipelines, or browser extensions:

### 1. Analyze Email
- **Endpoint**: `POST /api/analyze`
- **Headers**: `Content-Type: application/json`
- **Request Body**:
```json
{
  "sender": "security-alert@microsoft-phish.xyz",
  "recipient": "victim@domain.com",
  "subject": "URGENT: Password Reset Required",
  "body": "Your account has been locked. Verify your password at: http://login-microsoft-secure-auth.xyz/verify"
}
```
- **Response**: Full JSON diagnosis including `classification`, `risk_level`, `overall_risk_score`, `ml_confidence`, `scores`, `indicators`, `urls`, and `recommendations`.

### 2. Threat Statistics
- **Endpoint**: `GET /api/statistics` (Requires session authentication)

---

## 🚢 Production Deployment

### Option A: Render / Railway / Heroku
The project includes a production-ready `Procfile`:
```
web: gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 60
```
Set environment variables:
- `FLASK_ENV=production`
- `SECRET_KEY=<your-secret-key>`
- `DATABASE_URL=postgresql://...` (or use persistent disk with SQLite)

### Option B: Vercel
Configured via `vercel.json` and `wsgi.py`.

---

## 🛡️ Responsible Cybersecurity Notice
This application is strictly a **defensive security analysis tool**. It decomposes and evaluates email headers, lexical URL structures, and textual patterns locally without connecting to or executing suspicious links or payloads.
