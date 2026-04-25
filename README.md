╔══════════════════════════════════════════════════════════════╗
║       RAPTOR: THREAT ANALYZER  — SETUP GUIDE                ║
║       Moksh Shah | 250103003015 | MSc DFIS Sem 2 | NFSU     ║
║       Guide: Dr. Ramya Shah | Assistant Professor           ║
╚══════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PROJECT STRUCTURE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RAPTOR_4518 (2)/
├── backend/
│   └── app.py              ← Flask REST API (Python)
├── frontend/
│   └── index.html          ← Main UI (connects to backend)
├── database/               ← SQLite DB auto-created here
├── uploads/                ← Temp file storage
├── requirements.txt        ← Python dependencies
└── README.txt              ← This file

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
QUICK START (3 steps)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

STEP 1 — Install Python dependencies
    pip install -r requirements.txt
    OR
    pip install flask flask-cors requests scikit-learn numpy pandas

STEP 2 — Start the backend
    cd "RAPTOR_4518 (2)/backend"
    python app.py

    You should see:
    ╔══════════════════════════════╗
    ║  BACKEND RUNNING             ║
    ║  Open: http://localhost:5000 ║
    ╚══════════════════════════════╝

STEP 3 — Open the app
    Option A (recommended): Open http://localhost:5000
    Option B (standalone):  Open frontend/index.html directly in browser
                            (works without backend, local mode only)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MODES OF OPERATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ✅ API MODE (Flask running):
     - All scans saved to SQLite database permanently
     - Dashboard shows real database statistics
     - Scan history persists across browser sessions
     - VirusTotal + AbuseIPDB lookups (if API keys set)
     - Header shows: ● API ONLINE (green)

  ⚡ LOCAL MODE (no Flask):
     - All analysis runs in browser (JavaScript)
     - No persistent storage (history lost on refresh)
     - Still fully functional for ZIP/PS/URL analysis
     - PDF export still works
     - Header shows: ● LOCAL MODE (orange)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OPTIONAL: VirusTotal API
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Go to https://www.virustotal.com and create a free account
2. Go to your profile → API Key
3. Set it before running the backend:

   Windows (PowerShell):
       $env:VT_API_KEY = "your_key_here"
       python app.py

   Linux/Mac:
       export VT_API_KEY="your_key_here"
       python app.py

   OR edit app.py line 29:
       VT_API_KEY = "your_key_here"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
API ENDPOINTS (Flask Backend)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  POST  /api/scan/zip          Upload and scan a ZIP file
  POST  /api/scan/ps           Decode and analyze PowerShell
  POST  /api/scan/url          Analyze a URL for phishing
  POST  /api/extract/iocs      Extract IOCs from raw text
  POST  /api/scan/headers      Paste raw email headers → full analysis
  POST  /api/whois             Domain/URL → RDAP age + registrar info
  POST  /api/vt/hash           MD5/SHA1/SHA256 → full VT engine report

  GET   /api/history           Get all scan history
  GET   /api/history/<id>      Get single scan details
  GET   /api/stats             Dashboard statistics
  GET   /api/search/ioc?q=xx   Search IOC database
  GET   /api/health            Backend health check

  DELETE /api/history/<id>     Delete a scan record

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FEATURES 
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [✅] ZIP Scanner     — JSZip extraction, deep inspection of all file types
  [✅] PS Decoder      — Multi-layer (5-stage) decoding engine with 100+ detection rules
                        combining signature-based, heuristic, and behavioral analysis
  [✅] URL Analyzer    — phishing detection, redirect chain tracking, risk scoring
  [✅] IOC Extractor   — 9+ IOC types including dark web indicators
  [✅] Header Analyzer — SPF/DKIM/DMARC parsing, hop trace, originating IP detection
  [✅] WHOIS/Age Check — RDAP lookup, domain age analysis, new-domain risk flagging
  [✅] Hash Lookup     — VirusTotal engine report (MD5/SHA1/SHA256) with caching
  [✅] MITRE ATT&CK    — Comprehensive mapping to multiple MITRE tactics & techniques
  [✅] Entropy Scoring — Shannon entropy analysis for payload detection
  [✅] Advanced Detection Engine — Hybrid rule-based system with 100+ indicators
  [✅] Flask Backend   — REST API with full scan processing
  [✅] SQLite Database — persistent storage (scans, IOCs, files, MITRE hits)
  [✅] Dashboard       — real-time analytics from database
  [✅] PDF Export      — per-scan and full-session export
  [✅] Scan History    — persistent sidebar history tracking
  [✅] Dual Mode       — works with or without backend
  [✅] VirusTotal API  — integrated threat intelligence (API key required)
  [✅] Syntax Highlight — color-coded PowerShell decoding output
  [✅] IOC Copy        — one-click export of indicators

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NEW IN v7
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [✅] Email Header Analyzer — advanced parsing with authentication checks
  [✅] WHOIS / Domain Intelligence — registrar, expiry, domain age detection
  [✅] VirusTotal Hash Intelligence — full engine detection breakdown
  [✅] Dark Web IOC Detection — onion links, Telegram, paste services, anonymous hosts
  [✅] Enhanced Rule Engine — expanded from basic rules to 100+ detection indicators

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NOTES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️ IMPORTANT:
Use quotes when navigating folder:

    cd "RAPTOR_4518 (2)/backend"

Without quotes → command will fail due to space + parentheses.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━