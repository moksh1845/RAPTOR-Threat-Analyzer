# 🦅 RAPTOR — Threat Analyzer

RAPTOR is a modular static analysis platform designed to support **SOC triage, incident response, and threat intelligence workflows** by analyzing suspicious artifacts such as files, scripts, URLs, and emails.

The platform uses a **rule-based detection engine (100+ rules)** combined with heuristic and entropy-based analysis to identify malicious behavior and map it to **MITRE ATT&CK techniques**.

---

## 🧠 Analytical Scope

RAPTOR focuses on **pre-execution threat analysis**, enabling analysts to:

* Perform static inspection of suspicious artifacts
* Detect obfuscation, encoding, and staged payload delivery
* Extract and correlate Indicators of Compromise (IOCs)
* Map behaviors to MITRE ATT&CK techniques
* Support SOC-level triage and investigation workflows

---

## 🔥 Detection Engine

* **100+ heuristic and signature-based rules**
* Regex-based pattern matching with behavioral indicators
* Entropy analysis for detecting encoded/packed payloads
* Multi-layer decoding support
* Coverage includes:

  * Execution flags & evasion techniques
  * Network-based payload delivery
  * Persistence mechanisms
  * Suspicious file and URL patterns

---

## ⚙️ Core Modules

### 📦 Archive & File Analyzer

* Recursive ZIP extraction
* Detection of embedded payloads
* Suspicious file classification

---

### ⚡ PowerShell Analysis Engine

* Supports **text input + file upload (.ps1, .txt, logs)**
* Multi-layer decoding (Base64 / obfuscation handling)
* Detects execution flags:

  * `-EncodedCommand`, `-NoProfile`, `-WindowStyle Hidden`, `-NonInteractive`
* Identifies:

  * Droppers
  * Remote payload loaders
  * Staged execution chains
* Extracts embedded IOCs (URLs, IPs, commands)
* Entropy-based detection of encoded payloads

---

### 🌐 URL Intelligence Module

* Redirect chain analysis
* Phishing detection:

  * Brand impersonation
  * Suspicious TLDs
  * Parameter abuse (`cmd=`, `b64=`)
* Risk scoring based on indicators

---

### 📧 Email Threat Analyzer

* Header validation (SPF, DKIM, DMARC)
* Spoofing & impersonation detection
* Attachment risk analysis
* Credential harvesting pattern detection

---

### 🧬 IOC Extraction Engine

* IP addresses
* Domains
* URLs
* Hashes
* Email addresses

---

## 🎯 MITRE ATT&CK Integration

Automatically maps detected behaviors to techniques such as:

* T1059 — Command Execution
* T1027 — Obfuscated/Encoded Files
* T1105 — Ingress Tool Transfer
* T1562 — Defense Evasion
* T1218 — Signed Binary Proxy Execution

---

## 📊 Platform Capabilities

* 📁 **Dual Input Support** — Analyze via direct input or file upload
* Centralized dashboard with:

  * Threat scoring
  * IOC aggregation
  * MITRE technique tracking
* Structured outputs for analyst workflows
* Lightweight and extensible design

---

## 🛠️ Technology Stack

* **Backend:** Flask (Python)
* **Frontend:** HTML, CSS, JavaScript
* **Database:** SQLite
* **Detection:** Rule-based + Heuristic + Entropy

---

## 📂 Project Structure

```
RAPTOR-Threat-Analyzer/
│
├── backend/        # Analysis engine & API
├── frontend/       # UI layer
├── database/       # Local DB (excluded in production)
├── requirements.txt
└── README.md
```

---

## ⚙️ Setup Instructions

```bash
git clone https://github.com/your-username/RAPTOR-Threat-Analyzer.git
cd RAPTOR-Threat-Analyzer
pip install -r requirements.txt
python backend/app.py
```

---

## 📌 Use Cases

* SOC triage & alert investigation
* Malware static analysis
* Phishing analysis
* Threat intelligence enrichment
* Cybersecurity research & learning

---

## ⚠️ Disclaimer

This project is intended for **educational, research, and defensive security purposes only**.

---

## 👨‍💻 Author

**Moksh Shah**
M.Sc. Digital Forensics & Information Security
