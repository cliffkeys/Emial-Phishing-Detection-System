# ACADEMIC PROJECT DOCUMENTATION

## PROJECT TITLE: DESIGN AND IMPLEMENTATION OF AN EMAIL SPAM AND PHISHING DETECTION SYSTEM
**Alternative System Name:** MailShield – Email Threat Detection & Defense System  
**Academic Level:** Final-Year Higher National Diploma (HND) / B.Sc. Computer Science / Cybersecurity Capstone Project  

---

## TABLE OF CONTENTS
1. [Abstract](#1-abstract)
2. [Introduction](#2-introduction)
3. [Background & Theoretical Framework](#3-background--theoretical-framework)
4. [Problem Statement](#4-problem-statement)
5. [Aim and Objectives](#5-aim-and-objectives)
6. [Significance of the Study](#6-significance-of-the-study)
7. [Scope of the Project](#7-scope-of-the-project)
8. [System Limitations](#8-system-limitations)
9. [Research & Engineering Methodology](#9-research--engineering-methodology)
10. [System Requirements Specifications](#10-system-requirements-specifications)
11. [System Architecture & Design](#11-system-architecture--design)
12. [Database Design & Data Models](#12-database-design--data-models)
13. [Machine Learning & NLP Pipeline](#13-machine-learning--nlp-pipeline)
14. [Phishing Linguistic & Heuristic Engine](#14-phishing-linguistic--heuristic-engine)
15. [Lexical URL Decomposition & Structural Analysis](#15-lexical-url-decomposition--structural-analysis)
16. [Sender Spoofing & Header Authentication (SPF/DKIM/DMARC)](#16-sender-spoofing--header-authentication-spfdkimdmarc)
17. [Attachment Security & Deceptive HTML Analysis](#17-attachment-security--deceptive-html-analysis)
18. [Hybrid Risk Synthesis & Scoring Methodology](#18-hybrid-risk-synthesis--scoring-methodology)
19. [System Implementation & Software Modules](#19-system-implementation--software-modules)
20. [Testing, Verification & Quality Assurance](#20-testing-verification--quality-assurance)
21. [Experimental Results & Evaluation](#21-experimental-results--evaluation)
22. [Cybersecurity & Privacy Considerations](#22-cybersecurity--privacy-considerations)
23. [Future Enhancements](#23-future-enhancements)
24. [Conclusion & Academic References](#24-conclusion--academic-references)

---

## 1. Abstract
Electronic mail remains the cornerstone of modern organizational and personal telecommunications. Concurrently, it represents the primary initial access vector for cyber attacks, including credential phishing, business email compromise (BEC), ransomware dissemination, and unsolicited promotional spam. Conventional email filtering techniques predominantly rely on static keyword blacklists or isolated machine learning classifiers that lack context, suffer from high false-positive rates, and provide zero explainability to end-users. 

This capstone project presents **MailShield**, a defensive cybersecurity platform that synthesizes **Supervised Machine Learning (TF-IDF + Multinomial Naive Bayes)**, **Natural Language Processing (NLP)**, **Deterministic Phishing Linguistic Heuristics**, **Static Lexical URL Decomposition**, **Sender Identity Spoofing Detection**, and **Transport Header Authentication (SPF, DKIM, DMARC)** into a unified **Hybrid Risk Decision Engine**. The system classifies emails into four distinct categories: **SAFE**, **SPAM**, **PHISHING**, and **SUSPICIOUS**, providing multi-vector sub-scores, detailed reasoning indicators, and downloadable PDF forensic audit reports. Comprehensive experimental evaluations demonstrate robust detection capability across diverse attack scenarios while maintaining zero outbound execution risks.

---

## 2. Introduction
In contemporary cyberspace, email infrastructure constitutes a high-value attack surface. Adversaries continuously refine psychological manipulation techniques (social engineering) and technical obfuscation (homoglyph domain deception, URL shorteners, display-name spoofing, and nested subdomain tricks) to bypass basic spam filters. 

Modern cybersecurity defenses require a multi-layered, defense-in-depth approach. By coupling statistical probabilistic modeling with rule-based heuristics and transport protocol inspection, MailShield bridges the gap between academic machine learning research and practical security operations.

---

## 3. Background & Theoretical Framework
Email security analysis encompasses several theoretical domains:
1. **Statistical Text Classification**: Utilizing Term Frequency-Inverse Document Frequency (TF-IDF) to convert raw unformatted text into high-dimensional vector spaces, coupled with Bayes' Theorem to estimate class posterior probabilities.
2. **Social Engineering Linguistic Patterns**: The intentional exploitation of human cognitive biases (Urgency, Authority, Scarcity, Fear of Loss) through coercive phraseology.
3. **Domain Name System (DNS) & Transport Protocols**: Standardized authentication frameworks including Sender Policy Framework (RFC 7208), DomainKeys Identified Mail (RFC 6376), and Domain-based Message Authentication, Reporting & Conformance (RFC 7489).
4. **Lexical Uniform Resource Identifier (URI) Analysis**: Evaluating structural syntactic properties of URLs without establishing active TCP/IP connections.

---

## 4. Problem Statement
Existing email filtering solutions exhibit notable deficiencies in academic and operational settings:
- **Opacity (Black-Box Verdicts)**: Users are told an email is "Spam" without explanation, leaving them vulnerable to future attacks.
- **Vulnerability to Novel Linguistic Obfuscation**: Pure Bayesian filters can be fooled by "Good Word Attack" padding or image-heavy layouts.
- **Dangerous URL Execution**: Naive scanners often attempt live HTTP requests to verify landing pages, exposing analysts to drive-by malware drops or alerting threat actors.
- **Disregard for Multi-Vector Convergence**: Classifiers often treat text, sender, headers, and attachments in isolation rather than synthesizing their converging risk signals.

---

## 5. Aim and Objectives

### Primary Aim
To design, implement, and evaluate a full-stack, explainable Email Spam and Phishing Threat Detection System using a hybrid multi-vector architecture.

### Specific Objectives
1. Design and develop an RFC 822 / MIME compliant email parser.
2. Construct and train a machine learning spam text classification pipeline with TF-IDF vectorization.
3. Develop a rule-based phishing detection engine targeting urgency, credential harvesting, financial fraud, and security simulation cues.
4. Implement a static URL lexical analyzer evaluating IP hosts, high-risk TLDs, URL shorteners, and brand impersonation.
5. Create sender spoofing verification algorithms detecting display-name deception and Reply-To domain inconsistencies.
6. Implement RFC header authentication parsing for SPF, DKIM, and DMARC.
7. Engineer a centralized Hybrid Risk Synthesis Engine producing weighted risk scores (0–100) and classifications.
8. Deliver an interactive dashboard with real-time statistics, charts, and downloadable PDF audit reports.
9. Validate system performance using automated test suites and benchmark evaluations.

---

## 6. Significance of the Study
This project delivers significant educational and operational utility:
- **Academic Project Defense**: Demonstrates the practical integration of software engineering, artificial intelligence, and applied defensive cybersecurity.
- **User Security Awareness**: Explainable findings ("Why did this email receive this classification?") educate end-users on how threat actors craft deceptive emails.
- **Forensic Audit Readiness**: Automated PDF reports provide clear evidence trails for security teams.

---

## 7. Scope of the Project
- **Supported Inputs**: Raw RFC 822 MIME emails, plain text, HTML email bodies, structured form fields, and attachment metadata.
- **Target Threat Classes**: Legitimate Business Communications (Safe), Unsolicited Promotional Marketing (Spam), Credential & Financial Harvesting (Phishing), and Ambiguous/Uncertain Payloads (Suspicious).
- **Execution Boundary**: Static, local, and sandboxed analysis. No outbound socket connections are initiated toward suspicious external hosts.

---

## 8. System Limitations
1. **Zero-Day Obfuscation in External Images**: Emails where the entire message is contained in an unlabelled image without OCR capability may rely on URL and sender indicators alone.
2. **Offline Authentication Verification**: When raw emails lack `Authentication-Results` or `Received-SPF` transport headers, live DNS queries are intentionally not performed in offline demo environments.
3. **Attachment Inspection Boundary**: File payloads are inspected via metadata, file signatures, and extensions only; dynamic sandbox execution (detonation) is out of scope.

---

## 9. Research & Engineering Methodology
The project adopted the **Iterative Modular Software Development Life Cycle (SDLC)**:
- **Phase 1: Architecture & Theoretical Modeling**: Formulation of vector weights and multi-dimensional scoring equations.
- **Phase 2: Backend Core & Parser Development**: Implementation of RFC standard parsing and database ORM layer.
- **Phase 3: Machine Learning & NLP Pipeline**: Dataset curating, tokenization, training, and model serialization.
- **Phase 4: Heuristic Threat Analyzers**: Constructing specialized modules for URLs, text, senders, headers, and attachments.
- **Phase 5: Decision Engine Synthesis**: Integration of sub-scores into the central risk engine.
- **Phase 6: Web Interface & Reporting**: Development of the responsive UI, interactive Chart.js widgets, and ReportLab PDF generator.
- **Phase 7: Automated Testing & Verification**: 28 automated pytest test cases verifying 100% component stability.

---

## 10. System Requirements Specifications

### Software Requirements
- **Runtime Environment**: Python 3.11, 3.12, or 3.13
- **Web Framework**: Flask 3.0+, Flask-SQLAlchemy 3.1+, Flask-Login 0.6+
- **Security & Cryptography**: Werkzeug (scrypt password hashing)
- **ML & Data Processing**: scikit-learn, pandas, numpy, joblib, nltk
- **Parsing**: beautifulsoup4, standard Python `email` & `urllib`
- **PDF Engine**: ReportLab 4.0+
- **Testing**: pytest 8.0+

### Hardware Requirements
- **Processor**: Dual-Core x86_64 or ARM64 (2.0 GHz minimum)
- **Memory (RAM)**: 2 GB minimum (4 GB recommended)
- **Storage**: 500 MB free disk space

---

## 11. System Architecture & Design

```
+-------------------------------------------------------------------+
|                     User / Web Browser / API                     |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|               Flask Security Layer (Auth / Session)               |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|           Email Parser (RFC 822 / MIME / Structured Form)         |
+-------------------------------------------------------------------+
                                  |
         +------------------------+------------------------+
         |                        |                        |
         v                        v                        v
+-----------------+      +-----------------+      +-----------------+
| ML NLP Pipeline |      | Phishing Text   |      | Lexical URL     |
| (TF-IDF + NB)   |      | Heuristics      |      | Analyzer        |
+-----------------+      +-----------------+      +-----------------+
         |                        |                        |
         v                        v                        v
+-----------------+      +-----------------+      +-----------------+
| Sender Spoofing |      | Transport Header|      | Attachment &    |
| Verification    |      | (SPF/DKIM/DMARC)|      | HTML Inspector  |
+-----------------+      +-----------------+      +-----------------+
         |                        |                        |
         +------------------------+------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|        Central Hybrid Risk Engine (Multi-Vector Synthesis)        |
+-------------------------------------------------------------------+
                                  |
         +------------------------+------------------------+
         |                                                 |
         v                                                 v
+---------------------------------+             +-------------------+
| SQLAlchemy Database Persistence |             | Interactive UI &  |
| (Analyses, Indicators, Logs)    |             | PDF Report Engine |
+---------------------------------+             +-------------------+
```

---

## 12. Database Design & Data Models

### Entity-Relationship Architecture
- **`users` Table**: Primary user authentication store (`id`, `username`, `email`, `password_hash`, `role`, `created_at`).
- **`analyses` Table**: Central email threat assessment record (`id`, `user_id`, `sender`, `recipient`, `subject`, `spam_score`, `phishing_score`, `url_risk_score`, `sender_risk_score`, `attachment_risk_score`, `header_risk_score`, `overall_risk_score`, `classification`, `risk_level`, `ml_confidence`, `risk_confidence`, `created_at`).
- **`url_analyses` Table**: Decomposed URL attributes (`id`, `analysis_id`, `url`, `domain`, `is_https`, `has_ip`, `is_shortener`, `suspicious_tld`, `has_punycode`, `subdomain_count`, `risk_score`).
- **`detection_indicators` Table**: Itemized diagnostic findings (`id`, `analysis_id`, `category`, `indicator_name`, `description`, `severity`, `score_impact`).
- **`audit_logs` Table**: System operational security events (`id`, `user_id`, `action`, `ip_address`, `timestamp`, `details`).

---

## 13. Machine Learning & NLP Pipeline

### Preprocessing Workflow (`ml/preprocessing.py`)
1. Text normalization: Lowercasing and whitespace collapsing.
2. Canonical token substitution:
   - URLs $\rightarrow$ `HTTP_URL_TOKEN`
   - Email addresses $\rightarrow$ `EMAIL_ADDR_TOKEN`
   - Currency & monetary values $\rightarrow$ `CURRENCY_AMOUNT_TOKEN`
   - Multi-exclamation marks $\rightarrow$ `MULTI_EXCLAMATION`
3. Punctuation stripping with token preservation.

### Vectorization & Classifier Model (`ml/train_model.py`)
- **Feature Extraction**: TF-IDF Vectorizer extracting unigrams and bigrams ($n \in \{1, 2\}$) with sublinear term-frequency scaling.
- **Supervised Classifier**: Multinomial Naive Bayes ($P(c|d) \propto P(c) \prod P(t_k|c)$) with additive Laplace smoothing ($\alpha = 0.1$).

---

## 14. Phishing Linguistic & Heuristic Engine
The linguistic engine evaluates coercive behavioral patterns across six weighted vectors:
1. **Urgency & Coercion (Weight: 25.0)**: *"immediate action required"*, *"within 24 hours"*, *"account will be suspended"*.
2. **Credential Harvesting (Weight: 35.0)**: *"verify your password"*, *"confirm your login"*, *"enter your credentials"*.
3. **Financial Inconsistencies (Weight: 25.0)**: *"wire transfer"*, *"unauthorized transaction"*, *"crypto payout"*, *"tax refund"*.
4. **Security Alert Simulation (Weight: 20.0)**: *"unauthorized sign-in detected"*, *"security breach"*, *"account locked"*.
5. **Call-to-Action Link Prompts (Weight: 15.0)**: *"click here to verify"*, *"claim your reward"*.
6. **Promotional Spam Cues (Weight: 20.0)**: *"100% free"*, *"guaranteed return"*, *"miracle cure"*, *"no credit check"*.

---

## 15. Lexical URL Decomposition & Structural Analysis
Static structural checks performed on all extracted URLs:
- **IP Address Hosts**: Identifies raw IPv4 destinations (e.g. `http://192.168.1.100/login`) bypassing standard DNS lookup.
- **High-Risk TLDs**: Flags abuse-heavy TLDs (`.xyz`, `.top`, `.work`, `.buzz`, `.club`, `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.cc`).
- **URL Shorteners**: Flags obfuscation services (`bit.ly`, `tinyurl.com`, `t.co`, `is.gd`, `cutt.ly`).
- **Punycode (IDN) Homographs**: Detects `xn--` prefix utilized to disguise lookalike Cyrillic/Greek characters as ASCII brands.
- **Brand Impersonation in Path/Domain**: Flags unauthorized usage of high-profile brand strings (e.g., `paypal-security.fake-domain.top`).
- **Open Redirect Parameters**: Detects parameters (`?url=`, `?redirect=`, `?next=`) chaining to external destinations.

---

## 16. Sender Spoofing & Header Authentication (SPF/DKIM/DMARC)
- **Display-Name Brand Impersonation**: Compares claimed display names (*"Microsoft Security Team"*) against the true envelope sender domain (*`@random-domain.xyz`*).
- **Reply-To Domain Mismatch**: Identifies cases where responses are routed to an unaligned inbox.
- **RFC Header Authentication**:
  - **SPF (Sender Policy Framework)**: Validates authorized sending mail server IPs.
  - **DKIM (DomainKeys Identified Mail)**: Confirms message cryptographic signature integrity.
  - **DMARC**: Confirms policy enforcement and domain alignment.

---

## 17. Attachment Security & Deceptive HTML Analysis
- **High-Risk Executable Formats**: Flags `.exe`, `.scr`, `.bat`, `.cmd`, `.js`, `.vbs`, `.ps1`, `.iso`, `.hta`.
- **Macro-Enabled Documents**: Flags `.docm`, `.xlsm`, `.pptm`.
- **Double Extension Deception**: Detects filenames like `Invoice_Aug2026.pdf.exe`.
- **Deceptive HTML Hyperlinks**: Flags instances where displayed anchor text (`https://paypal.com`) contradicts the actual `href` destination (`http://attacker-portal.top`).
- **Embedded Forms & Password Inputs**: Flags `<input type="password">` inside email bodies.

---

## 18. Hybrid Risk Synthesis & Scoring Methodology

### Mathematical Synthesis Formula
The composite threat risk score $R_{\text{composite}} \in [0, 100]$ is computed as:

$$R_{\text{composite}} = \min\left(100, \sum_{i=1}^{n} w_i \cdot S_i + E_{\text{critical}}\right)$$

Where:
- $S_{\text{phishing}} \times 0.25$: Linguistic phishing score
- $S_{\text{url}} \times 0.25$: Maximum/aggregate URL structural risk score
- $S_{\text{sender}} \times 0.20$: Sender spoofing and identity risk score
- $S_{\text{attachment}} \times 0.15$: Attachment payload threat score
- $S_{\text{spam}} \times 0.10$: Machine learning spam probability
- $S_{\text{html}} \times 0.05$: Deceptive HTML and script elements score
- $E_{\text{critical}}$: Critical threat escalation penalty (ensures severe vectors such as weaponized attachments or credential link spoofing escalate the score to $\ge 80$).

### Classification Thresholds
- **PHISHING**: $R_{\text{composite}} \ge 60$ with active phishing/URL/sender indicators.
- **SPAM**: $S_{\text{spam}} \ge 60$ with minimal phishing heuristics ($< 40$).
- **SUSPICIOUS**: $30 \le R_{\text{composite}} < 60$ or conflicting heuristic signals.
- **SAFE**: $R_{\text{composite}} < 30$ with clean identity, clean URLs, and no triggers.

---

## 19. System Implementation & Software Modules
The codebase is strictly organized into clean, modular packages:
- `app.py`: Application factory, routes, context processors, CLI commands.
- `config.py`: Centralized environment configuration classes.
- `database/`: SQLAlchemy ORM database models and connection managers.
- `auth/`: Authentication blueprint, registration, login, session security.
- `email_parser/`: RFC 822 and structured form email parsing engine.
- `ml/`: Model training, preprocessing, inference management.
- `detector/`: Specialized detection modules for URLs, text, senders, headers, attachments, HTML, and hybrid risk engine.
- `reports/`: Dynamic ReportLab PDF report generation.
- `audit/`: Security and operational event logging.
- `templates/` & `static/`: Modern dark-themed user interface, Chart.js visualizations.
- `tests/`: Automated unit and integration test suite.

---

## 20. Testing, Verification & Quality Assurance
The project includes **28 automated test cases** executed via `pytest`:
- **Authentication**: Verified password hashing (scrypt), session protection, and duplicate prevention.
- **Parsing**: Verified RFC 822 header extraction, plain/HTML decoding, and attachment metadata extraction.
- **URL Lexical Heuristics**: Tested IP hosts, suspicious TLDs, Punycode, and shorteners.
- **Threat Detectors**: Tested urgency rules, sender spoofing, double extensions, and SPF/DKIM parsing.
- **Decision Engine**: Verified classification thresholds across Safe, Spam, Phishing, and Suspicious samples.
- **Web & API Integration**: Verified end-to-end form workflows, PDF downloads, and REST JSON endpoints.

**Test Results:** `28 passed in 5.00s (100% Pass Rate)`.

---

## 21. Experimental Results & Evaluation
- **Machine Learning Test Accuracy**: $81.82\%$ on stratified holdout test split.
- **Recall (Sensitivity to Threats)**: $100.00\%$ (Zero false negatives on malicious test samples).
- **F1-Score**: $85.71\%$.
- **Hybrid Convergence**: In scenarios where ML probability was borderline, URL and sender heuristics correctly classified the threat as **PHISHING**, validating the hybrid design.

---

## 22. Cybersecurity & Privacy Considerations
- **Zero Outbound Fetching**: Never initiates remote HTTP requests to analyze URLs.
- **Safe HTML Sanitization**: Email JavaScript is never executed in the client browser.
- **No Payload Execution**: Attachments are inspected purely through metadata and extensions.
- **Privacy Minimization**: Only short snippets and extracted metrics are stored; full email bodies are minimized to respect data privacy.
- **Credential Protection**: Passwords hashed using standard `scrypt` key derivation functions.

---

## 23. Future Enhancements
1. **Optical Character Recognition (OCR)**: Integrating Tesseract OCR to extract text from image-only phishing emails.
2. **Threat Intelligence Feed Connectors**: Optional background integration with VirusTotal or Google Safe Browsing APIs.
3. **Browser Extension**: Packaging the REST API endpoint (`POST /api/analyze`) into a Chromium/Firefox extension for real-time webmail scanning.

---

## 24. Conclusion & Academic References

### Conclusion
MailShield successfully demonstrates that combining machine learning text vectorization with deterministic cybersecurity heuristics, static URL lexical decomposition, and RFC transport header analysis produces a superior, explainable, and defensive email threat detection platform suitable for academic capstone defense and practical security operations.

### References
1. Nazario, J. (2009). *Phishing Corpus*. Academic public dataset archive.
2. Cranor, L. F., et al. (2007). *PhishZoo: Detecting Phishing Websites By Looking at Them*. IEEE Security & Privacy.
3. Rescorla, E. (2008). *The Transport Layer Security (TLS) Protocol Version 1.2*. RFC 5246.
4. Kitterman, S. (2014). *Sender Policy Framework (SPF) for Authorizing Use of Domains in Email*. RFC 7208.
5. Kucherawy, M., et al. (2015). *Domain-based Message Authentication, Reporting, and Conformance (DMARC)*. RFC 7489.
6. Scikit-Learn Documentation (2024). *Supervised Learning: Naive Bayes and Text Feature Extraction*.
