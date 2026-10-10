# AGEINS AI - Next-Gen Multi-Source Cyber Defense & Deepfake Forensics Platform

**AGEINS** is an enterprise-grade cybersecurity web platform engineered to detect modern online fraud, phishing links, social engineering scams, and multi-modal synthetic media (deepfake images, audios, and videos) with real-time multi-source intelligence, AI conversational support, and role-based operational control.

---

## 🌟 Key Platform Modules & Features

### 1. Multi-Source Threat & Deepfake Detection Engine
- **Phishing & Lookalike URLs**: Analyzes domain typosquatting, Levenshtein brand distance, high-entropy DGA strings, suspicious TLDs (`.xyz`, `.top`, `.buzz`), unencrypted HTTP schemes, and IP address hosts.
- **Scam & Fraud Text / Emails**: Detects urgency triggers, banking coercion (e.g. SBI/HDFC/KYC scams), digital arrest threats, advance-fee lures, and credential-harvesting triggers.
- **Image Deepfake Forensics**: Runs **Error Level Analysis (ELA)** to expose re-compression discrepancies, plus **2D Fast Fourier Transform (FFT)** to reveal GAN/Diffusion up-convolution periodic noise markers.
- **Audio / Voice Clone Forensics**: Evaluates acoustic waveforms, zero-crossing rates (ZCR), vocoder energy smoothing (HiFi-GAN/VITS artifacts), and unnatural inter-phoneme room silence floors.
- **Video Deepfake Forensics**: Samples temporal keyframes across the playback timeline to detect inter-frame jitter, structural flickering, facial boundary warping, and compression disparity.

### 2. Role-Based Dual Portals

#### 👤 User Portal (`dashboard.html` & `threat.html`)
- **Interactive Multi-Vector Scanner**: Seamless tabs to scan links, text, images, audios, and videos.
- **Visual Telemetry & Gauge**: 0–100% dynamic risk index, severity tags, and security recommendations.
- **Personal Security Dashboard**: Tracks total scans, blocked infiltrations, and clean posture scores.
- **User Data Protection Shield**:
  - Client-side PII masking (redacts phone numbers and account identifiers).
  - One-way SHA-256 cryptographic hashing (no plaintext payload storage).
  - Ephemeral in-memory forensic processing with session scrub capabilities.
- **Emergency Helpline Guide**: Quick actions for national reporting (Call **1930** / [cybercrime.gov.in](https://cybercrime.gov.in)) and banking freezes.

#### 🛡️ Administrator & Organiser Operations Portal (`admin.html`)
- **Access Control (RBAC)**: Manage Super Admins, Security Analysts, Compliance Auditors, and Users with real-time permission and status updates.
- **Control Center (Threat Quarantine)**: Inspect, isolate, or release suspicious payloads and malicious domains; broadcast system-wide emergency alerts.
- **Configuration Panel**: Fine-tune detection sensitivity, deepfake spectral thresholds, auto-quarantine risk cutoffs, and data retention windows (7 to 90 days).
- **Multi-Source Detection Feeds**: Live health telemetry across all intelligence feeds (Neural Heuristics, Spectral FFT, Acoustic ASV, Global Feeds, NLP Classifiers).
- **Security Operations Audit Log**: Timestamped immutable operational ledger.

### 3. AI Cyber Assistant (ShieldBot)
- Persistent floating cyber copilot available across all pages (`chatbot.js`).
- Fluent in **English** and **Hinglish/Hindi** for natural, user-friendly communication.
- Instant threat scanning directly from the chat interface (paste any link or message to get a risk score).
- Step-by-step guidance for cyber attacks, digital arrest scams, deepfake identification, and account recovery.

---

## 🚀 Running the Application

### Backend API (FastAPI)
The backend defaults to port `8001`, but you can override it with the `AGEINS_PORT` environment variable if another service already owns that port:
```powershell
cd "C:\Users\swapna sethi\.gemini\antigravity\scratch\ageins\backend"
$env:AGEINS_PORT = "8123"
python -m uvicorn main:app --host 127.0.0.1 --port $env:AGEINS_PORT --reload
```
- API Docs: `http://127.0.0.1:8123/docs`
- Health check: `http://127.0.0.1:8123/api/health`

If you change the backend port, point the frontend to the same backend with a URL parameter or browser storage override:
```javascript
localStorage.setItem("AGEINS_API_BASE", "http://127.0.0.1:8123");
```
Or open the page with:
```text
http://localhost:5500/threat.html?apiBase=http://127.0.0.1:8123
```

### Frontend Application
The frontend is hosted on port `5500`:
```powershell
cd "C:\Users\swapna sethi\.gemini\antigravity\scratch\ageins\FRONTEND"
python -m http.server 5500
```
Open in browser:
- **Home**: `http://localhost:5500/index.html`
- **Threat Scanner**: `http://localhost:5500/threat.html`
- **User Dashboard**: `http://localhost:5500/dashboard.html`
- **Admin Portal**: `http://localhost:5500/admin.html`

---

## 🔒 Data Protection & Security Mindset
1. **Zero-Knowledge Forensics**: Scanned file buffers are inspected in volatile memory and purged immediately.
2. **SHA-256 One-Way Hashing**: Scan history stores cryptographic fingerprints rather than sensitive raw payloads.
3. **Role-Based Isolation**: Access to sensitive admin controls and quarantine vaults is strictly governed.
