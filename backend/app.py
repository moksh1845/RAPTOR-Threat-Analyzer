"""
╔══════════════════════════════════════════════════════════╗
║      MINI THREAT ANALYZER v4 — FLASK BACKEND            ║
║      Moksh Shah | MSc DFIS | Enroll: 250103003015       ║
╠══════════════════════════════════════════════════════════╣
║  HOW TO RUN:                                            ║
║    pip install flask flask-cors requests                ║
║    python app.py                                        ║
║  Then open: http://localhost:5000                       ║
╚══════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3, os, json, hashlib, base64, re, zipfile, io
import datetime, math, pickle, numpy as np
from urllib.parse import urlparse

# ── CONFIG ────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, '..', 'database', 'threat_analyzer.db')
FRONTEND   = os.path.join(BASE_DIR, '..', 'frontend')
UPLOAD_DIR = os.path.join(BASE_DIR, '..', 'uploads')
MODEL_DIR  = os.path.join(BASE_DIR, '..', 'model')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# ── API KEYS ──────────────────────────────────────────────
VT_API_KEY    = os.environ.get('VT_API_KEY', '')
ABUSE_API_KEY = os.environ.get('ABUSE_API_KEY', '')

app = Flask(__name__, static_folder=FRONTEND)
CORS(app)

# ══════════════════════════════════════════════════════════
# ML MODEL LOADER
# ══════════════════════════════════════════════════════════
ML_MODEL       = None
ML_FEATURES    = None
ML_METADATA    = None

def load_ml_model():
    global ML_MODEL, ML_FEATURES, ML_METADATA
    try:
        model_path = os.path.join(MODEL_DIR, 'phishing_model.pkl')
        feat_path  = os.path.join(MODEL_DIR, 'feature_names.json')
        meta_path  = os.path.join(MODEL_DIR, 'model_metadata.json')
        if os.path.exists(model_path):
            with open(model_path,'rb') as f: ML_MODEL = pickle.load(f)
            with open(feat_path,'r')   as f: ML_FEATURES = json.load(f)
            with open(meta_path,'r')   as f: ML_METADATA = json.load(f)
            print(f"  ✅ ML Model loaded — Accuracy: {ML_METADATA['accuracy']}%")
        else:
            print("  ⚠️  ML model not found. Run: python train_model.py")
    except Exception as e:
        print(f"  ❌ ML model load error: {e}")

load_ml_model()

# ── ML FEATURE EXTRACTION ─────────────────────────────────
SUSP_TLDS_ML   = {'.xyz','.tk','.ml','.ga','.cf','.gq','.pw','.top',
                  '.click','.online','.site','.buzz','.icu','.fun'}
BRAND_KW_ML    = ['paypal','amazon','microsoft','apple','google','facebook',
                  'instagram','netflix','coinbase','binance','bankof','hsbc',
                  'wellsfargo','chase','citibank','linkedin','twitter',
                  'dropbox','spotify','steam','verify','secure','login',
                  'signin','account','update','confirm','billing','alert']
SHORTENER_ML   = {'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly',
                  'is.gd','buff.ly','rb.gy','cutt.ly','short.io'}
SUSP_PARAMS_ML = ['cmd','exec','payload','shell','invoke','bypass','run',
                  'b64','enc','install','setup','download','token','redirect']

def extract_ml_features(url):
    try:
        parsed = urlparse(url if url.startswith('http') else 'https://'+url)
        host   = (parsed.hostname or '').lower()
        path   = parsed.path or '/'
        query  = parsed.query or ''
        parts  = [p for p in host.split('.') if p]
    except:
        host=''; path='/'; query=''; parts=[]

    tld = '.'+parts[-1] if parts else ''
    return [
        len(url),
        len(host),
        url.count('.'),
        host.count('-'),
        sum(c.isdigit() for c in host),
        max(0, len(parts)-2),
        1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host) else 0,
        1 if url.startswith('https') else 0,
        1 if tld in SUSP_TLDS_ML else 0,
        1 if any(b in host for b in BRAND_KW_ML) else 0,
        sum(1 for b in BRAND_KW_ML if b in host),
        1 if host in SHORTENER_ML else 0,
        sum(1 for k in SUSP_PARAMS_ML if k in query.lower() or k in path.lower()),
        len(query),
        len(query.split('&')) if query else 0,
        len(path),
        path.count('/'),
        1 if '@' in url else 0,
        1 if '//' in path else 0,
        1 if '%' in url else 0,
        1 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', query) else 0,
        sum(1 for c in url if c in '-_~:/?#[]@!$&\'()*+,;=%'),
    ]

def ml_predict(url):
    """Run ML model prediction on a URL."""
    if ML_MODEL is None:
        return {"available": False, "error": "Model not loaded. Run train_model.py first."}
    try:
        features = np.array([extract_ml_features(url)])
        pred     = ML_MODEL.predict(features)[0]
        proba    = ML_MODEL.predict_proba(features)[0]
        conf     = float(proba[pred])
        feat_imp = ML_METADATA.get('feature_importances', {})
        feat_vals = dict(zip(ML_FEATURES, features[0]))

        # Top contributing features
        top_feats = sorted(
            [(f, feat_imp.get(f,0), float(feat_vals.get(f,0)))
             for f in ML_FEATURES],
            key=lambda x: x[1], reverse=True
        )[:8]

        return {
            "available":    True,
            "prediction":   "PHISHING" if pred==1 else "LEGITIMATE",
            "label":        int(pred),
            "confidence":   round(conf*100, 2),
            "phishing_prob":round(float(proba[1])*100, 2),
            "legit_prob":   round(float(proba[0])*100, 2),
            "top_features": [{"name":f, "importance":round(i*100,2), "value":round(v,2)} for f,i,v in top_feats],
            "model_accuracy": ML_METADATA.get('accuracy', 0),
            "algorithm":    "Random Forest (150 trees)",
            "trained_on":   "10,000 URLs (5,000 phishing + 5,000 legitimate)",
        }
    except Exception as e:
        return {"available": False, "error": str(e)}

# ══════════════════════════════════════════════════════════
# DATABASE SETUP
# ══════════════════════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS scans (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type   TEXT NOT NULL,
        target_name TEXT NOT NULL,
        risk_level  TEXT NOT NULL,
        risk_score  INTEGER NOT NULL,
        summary     TEXT,
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS iocs (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id    INTEGER REFERENCES scans(id) ON DELETE CASCADE,
        ioc_type   TEXT NOT NULL,
        value      TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS files (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id    INTEGER REFERENCES scans(id) ON DELETE CASCADE,
        file_path  TEXT,
        file_ext   TEXT,
        file_size  INTEGER,
        risk_score INTEGER,
        encoding   TEXT,
        entropy    REAL,
        decoded    TEXT,
        indicators TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS mitre_hits (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id   INTEGER REFERENCES scans(id) ON DELETE CASCADE,
        technique TEXT NOT NULL,
        name      TEXT,
        tactic    TEXT
    );
    CREATE TABLE IF NOT EXISTS vt_cache (
        hash      TEXT PRIMARY KEY,
        result    TEXT,
        cached_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_scans_type  ON scans(scan_type);
    CREATE INDEX IF NOT EXISTS idx_iocs_scan   ON iocs(scan_id);
    CREATE INDEX IF NOT EXISTS idx_iocs_value  ON iocs(value);
    """)
    conn.commit()
    conn.close()

init_db()

# ══════════════════════════════════════════════════════════
# ANALYSIS ENGINE
# ══════════════════════════════════════════════════════════
PS_RULES = [
    {"kw":["invoke-expression","iex"],                       "tag":"CRITICAL","score":30,"txt":"Invoke-Expression (IEX) — executes strings as code, #1 obfuscation bypass.","mitre":"T1059.001"},
    {"kw":["downloadstring","downloadfile","net.webclient"], "tag":"HIGH",    "score":25,"txt":"WebClient download — fetches and executes payload from remote C2.","mitre":"T1105"},
    {"kw":["bypass","executionpolicy"],                      "tag":"HIGH",    "score":20,"txt":"ExecutionPolicy bypass — disables PS script security restrictions.","mitre":"T1059.001"},
    {"kw":["windowstyle hidden","-w hidden"],                "tag":"HIGH",    "score":18,"txt":"Hidden window — process runs silently in background.","mitre":"T1059.001"},
    {"kw":["set-mppreference","disablerealtimemonitoring"],  "tag":"CRITICAL","score":35,"txt":"Windows Defender disabled — real-time AV protection killed.","mitre":"T1562.001"},
    {"kw":["amsiutils","amsi.dll","[ref].assembly"],         "tag":"CRITICAL","score":30,"txt":"AMSI bypass — Antimalware Scan Interface patched.","mitre":"T1562.001"},
    {"kw":["invoke-mimikatz","sekurlsa","lsadump"],          "tag":"CRITICAL","score":40,"txt":"Mimikatz — dumps LSASS passwords and NTLM hashes.","mitre":"T1003"},
    {"kw":["tcpclient","udpclient","net.sockets"],           "tag":"HIGH",    "score":25,"txt":"Raw TCP socket — reverse shell or C2 channel.","mitre":"T1049"},
    {"kw":["schtasks","new-scheduledtask"],                  "tag":"HIGH",    "score":18,"txt":"Scheduled task persistence.","mitre":"T1053.005"},
    {"kw":["reg add","currentversion\\run"],                 "tag":"HIGH",    "score":20,"txt":"Registry Run key — boot persistence.","mitre":"T1547.001"},
    {"kw":["net user","net localgroup administrators"],      "tag":"HIGH",    "score":22,"txt":"Account manipulation — backdoor or privilege escalation.","mitre":"T1136"},
    {"kw":["frombase64string","convert::frombase64"],        "tag":"MEDIUM",  "score":12,"txt":"Runtime base64 decode — multi-layer obfuscation.","mitre":"T1027"},
    {"kw":["start-process","shellexecute","createprocess"],  "tag":"MEDIUM",  "score":12,"txt":"Process spawning — dropper/loader chain.","mitre":"T1055"},
    {"kw":["-noprofile","-nop"],                             "tag":"MEDIUM",  "score": 8,"txt":"-NoProfile — bypasses profile-based logging.","mitre":""},
    {"kw":["pastebin.com","hastebin",".onion","transfer.sh"],"tag":"HIGH",    "score":20,"txt":"Suspicious C2 source — paste site or dark web.","mitre":"T1105"},
    {"kw":["virtualallocex","writeprocessmemory"],           "tag":"CRITICAL","score":35,"txt":"Process injection — shellcode into remote process.","mitre":"T1055"},
    {"kw":["send-mailmessage","uploadfile","uploadstring"],  "tag":"HIGH",    "score":18,"txt":"Data exfiltration to external server.","mitre":"T1041"},
    {"kw":["remove-item","del /f","rd /s"],                  "tag":"MEDIUM",  "score":10,"txt":"File deletion — anti-forensics.","mitre":"T1070.004"},
    {"kw":["%appdata%","%temp%","%localappdata%"],           "tag":"MEDIUM",  "score":10,"txt":"Staging in temp dirs — evades AV scanning.","mitre":"T1027"},
]

MITRE_DB = {
    "T1059.001":("PowerShell","Execution"),
    "T1027":    ("Obfuscated Files","Defense Evasion"),
    "T1105":    ("Ingress Tool Transfer","C&C"),
    "T1562.001":("Disable Security Tools","Defense Evasion"),
    "T1003":    ("Credential Dumping","Credential Access"),
    "T1049":    ("System Network Connections","Discovery"),
    "T1053.005":("Scheduled Task","Persistence"),
    "T1547.001":("Registry Run Keys","Persistence"),
    "T1136":    ("Create Account","Persistence"),
    "T1055":    ("Process Injection","Defense Evasion"),
    "T1070.004":("File Deletion","Defense Evasion"),
    "T1041":    ("Exfiltration over C2","Exfiltration"),
}

DANGEROUS = {'.exe','.dll','.bat','.cmd','.vbs','.js','.jse','.wsf','.wsh','.hta','.scr','.pif','.com','.lnk','.msi','.reg','.cpl','.iso'}
SCRIPTS   = {'.ps1','.psm1','.psd1','.py','.sh','.bash','.rb','.php','.pl'}
DOCUMENTS = {'.docm','.xlsm','.pptm','.doc','.xls','.pdf','.odt'}
ARCHIVES  = {'.zip','.rar','.7z','.tar','.gz','.cab'}

def risk_level(score):
    return "HIGH" if score>=70 else "MEDIUM" if score>=35 else "LOW"

def eml_risk_level(score):
    """Email-specific thresholds — lower bar for HIGH because phishing
    signals are concentrated in individual components (headers / attachments)
    and get diluted by weighted averaging."""
    return "HIGH" if score>=60 else "MEDIUM" if score>=28 else "LOW"

def shannon_entropy(data):
    if not data: return 0.0
    freq = {}
    for c in data: freq[c] = freq.get(c,0)+1
    n = len(data)
    return -sum((f/n)*math.log2(f/n) for f in freq.values())

# ── ALLOWED UPLOAD EXTENSIONS ────────────────────────────
ALLOWED_UPLOAD_EXTS = {'.txt', '.log', '.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.vbs', '.js', '.hta', '.py', '.sh'}
MAX_UPLOAD_BYTES    = 5 * 1024 * 1024   # 5 MB

# ── SUSPICIOUS EXTENSION PATTERNS ────────────────────────
SUSP_EXTENSIONS = {
    '.hta':  ('CRITICAL', 40, 'HTA file — HTML Application, direct exec without sandbox.', 'T1218.005'),
    '.exe':  ('CRITICAL', 40, 'Executable dropped/referenced in script.', 'T1204.002'),
    '.bat':  ('HIGH',     25, 'Batch script — common dropper/loader.', 'T1059.003'),
    '.cmd':  ('HIGH',     22, 'CMD script — command execution.', 'T1059.003'),
    '.vbs':  ('HIGH',     22, 'VBScript — scriptlet / WSH execution.', 'T1059.005'),
    '.js':   ('HIGH',     20, 'JavaScript — JScript WSH execution.', 'T1059.007'),
    '.jse':  ('CRITICAL', 30, 'Encoded JScript — obfuscated execution.', 'T1059.007'),
    '.wsf':  ('HIGH',     22, 'Windows Script File — multi-language payload.', 'T1059.005'),
    '.wsh':  ('HIGH',     20, 'Windows Scripting Host — automation abuse.', 'T1059.005'),
    '.scr':  ('CRITICAL', 35, 'Screensaver PE — executable disguise.', 'T1204.002'),
    '.pif':  ('CRITICAL', 35, 'PIF file — executable, ignored by email filters.', 'T1204.002'),
    '.dll':  ('HIGH',     28, 'DLL reference — side-loading / reflective injection.', 'T1055.001'),
    '.lnk':  ('HIGH',     22, 'Shortcut file — common spear-phishing vector.', 'T1547.009'),
    '.iso':  ('HIGH',     18, 'ISO/IMG — bypasses Mark-of-the-Web.', 'T1553.005'),
    '.msi':  ('HIGH',     18, 'MSI installer — abused for LOLBAS execution.', 'T1218.007'),
    '.cpl':  ('HIGH',     28, 'Control Panel item — signed proxy execution.', 'T1218.002'),
    '.ps1':  ('MEDIUM',   10, 'PowerShell script file reference.', 'T1059.001'),
}

# ── EXECUTION FLAG PATTERNS ───────────────────────────────
EXEC_FLAGS = [
    (r'-(?:exec(?:utionpolicy)?|ep)\s+bypass',                             'CRITICAL', 30, '-ExecutionPolicy Bypass — skips all PS script signing checks.', 'T1059.001'),
    (r'-(?:w(?:indowstyle)?\s+h(?:idden)?|win\s+hid)',                     'HIGH',     18, '-WindowStyle Hidden — stealth execution, no UI.', 'T1059.001'),
    (r'-(?:nop(?:rofile)?)',                                                'MEDIUM',   10, '-NoProfile — bypasses profile-based logging & restrictions.', 'T1059.001'),
    (r'-(?:noni(?:nteractive)?)',                                           'MEDIUM',    8, '-NonInteractive — no user prompts, typical dropper flag.', 'T1059.001'),
    (r'-(?:e(?:nc(?:odedcommand)?)?)\s+[A-Za-z0-9+/=]{10,}',              'HIGH',     20, '-EncodedCommand — base64 payload to evade CLI logging.', 'T1027'),
    (r'-(?:c(?:ommand)?)\s+["\'].*["\']',                                  'MEDIUM',   10, '-Command string — inline script execution.', 'T1059.001'),
    (r'(?:set-)?executionpolicy\s+unrestricted',                           'HIGH',     20, 'ExecutionPolicy Unrestricted — fully disables script lockdown.', 'T1059.001'),
    (r'-(?:sta|mta)',                                                       'LOW',       5, '-STA/-MTA threading — often combined with shellcode loaders.', ''),
]

# ── SUSPICIOUS URL/DOMAIN PATTERNS ───────────────────────
SUSP_URL_PATTERNS = [
    (r'https?://\d{1,3}(?:\.\d{1,3}){3}[:/]',                              'CRITICAL', 30, 'Raw IP address C2 — avoids DNS sinkholes.', 'T1071.001'),
    (r'https?://[^/\s]{0,60}\.(?:xyz|tk|ml|ga|cf|gq|pw|top|click|online|site|buzz|icu|fun|zip)[/\s"\']', 'HIGH', 22, 'Suspicious TLD in URL — common phishing/malware hosting.', 'T1071.001'),
    (r'(?:pastebin\.com|raw\.githubusercontent|ghostbin\.co|hastebin|rentry\.co|paste\.sh|0paste|justpaste\.it)', 'HIGH', 20, 'Paste/code-share C2 — hosted payload retrieval.', 'T1105'),
    (r'(?:transfer\.sh|anonfiles\.com|file\.io|ufile\.io|gofile\.io)',      'HIGH',     22, 'Anonymous file host — payload staging.', 'T1105'),
    (r'(?:bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|rb\.gy|is\.gd)',            'MEDIUM',   15, 'URL shortener — C2 redirect chain.', 'T1071.001'),
    (r'\.hta(?:["\'\s?#]|$)',                                               'CRITICAL', 35, 'HTA file URL — direct HTML Application execution.', 'T1218.005'),
    (r'(?:cmd=|exec=|payload=|shell=|invoke=|bypass=|run=|b64=|enc=)',     'HIGH',     18, 'Suspicious query parameter — server-side exec.', 'T1059'),
    (r'\.(?:exe|dll|bat|scr|pif|ps1|vbs|js|hta)\b',                        'HIGH',     20, 'Executable extension in URL — download & exec pattern.', 'T1105'),
    (r'(?:updater?|update|install|setup|patch|payload|dropper|loader|stager|stage\d?)\.',  'MEDIUM', 12, 'Deceptive filename keyword in URL.', 'T1036'),
]

# ── ENHANCED OBFUSCATION PATTERNS ────────────────────────
OBFUSC_PATTERNS = [
    (r'\$(?:env:)?(?:comspec|programdata|temp|appdata|localappdata|public)\b', 'MEDIUM', 12, 'Env-var staging path — AV-evasion dropper location.', 'T1027'),
    (r'(?:\[char\]|\[convert\]|char\(\d+\))',                               'HIGH',     18, 'Char-code obfuscation — string assembly to bypass detection.', 'T1027'),
    (r'\$(?:\{[^}]+\}|[a-z_]\w*)\s*=\s*["\'][A-Za-z0-9+/]{30,}={0,2}["\']', 'MEDIUM', 12, 'Variable-stored Base64 — staged decode.', 'T1027'),
    (r'(?:`[a-z]){3,}',                                                     'HIGH',     15, 'Backtick escape obfuscation — breaks string detection.', 'T1027'),
    (r'(?:replace|split|join|reverse)\s*\(',                                'MEDIUM',    8, 'String manipulation — classic obfuscation technique.', 'T1027'),
    (r'\[regex\]::|\[string\]::',                                           'MEDIUM',   10, 'Reflection string ops — evasion via .NET classes.', 'T1027'),
    (r'(?:compress-archive|expand-archive|deflatestream|gzipstream)',       'HIGH',     15, 'Compression — packed/staged payload.', 'T1027.002'),
]


def detect_susp_extensions(text):
    """Scan raw text for referenced suspicious file extensions."""
    findings = []
    seen = set()
    for match in re.finditer(r'[\w\-. ]+?(\.(?:hta|exe|bat|cmd|vbs|js|jse|wsf|wsh|scr|pif|dll|lnk|iso|msi|cpl|ps1))\b', text, re.I):
        ext = match.group(1).lower()
        context = text[max(0,match.start()-30):match.end()+30].strip()
        key = ext + '|' + match.group(0)[:40]
        if key not in seen and ext in SUSP_EXTENSIONS:
            seen.add(key)
            tag, score, desc, mitre = SUSP_EXTENSIONS[ext]
            findings.append({'ext': ext, 'tag': tag, 'score': score,
                              'text': desc, 'mitre': mitre, 'context': context[:120]})
    return findings


def detect_exec_flags(text):
    """Detect PowerShell execution flags that indicate malicious invocation."""
    findings = []
    for pattern, tag, score, desc, mitre in EXEC_FLAGS:
        if re.search(pattern, text, re.I):
            findings.append({'tag': tag, 'score': score, 'text': desc, 'mitre': mitre})
    return findings


def detect_susp_urls(text):
    """Detect suspicious URL patterns and flag domains/extensions."""
    findings = []
    seen_desc = set()
    for pattern, tag, score, desc, mitre in SUSP_URL_PATTERNS:
        m = re.search(pattern, text, re.I)
        if m and desc not in seen_desc:
            seen_desc.add(desc)
            context = text[max(0,m.start()-20):m.end()+40].strip()
            findings.append({'tag': tag, 'score': score, 'text': desc,
                              'mitre': mitre, 'context': context[:120]})
    return findings


def detect_obfuscation(text):
    """Detect obfuscation techniques beyond basic PS rules."""
    findings = []
    seen = set()
    for pattern, tag, score, desc, mitre in OBFUSC_PATTERNS:
        if re.search(pattern, text, re.I) and desc not in seen:
            seen.add(desc)
            findings.append({'tag': tag, 'score': score, 'text': desc, 'mitre': mitre})
    return findings


def build_enhanced_analysis(raw_text, decoded_text, filename=None):
    """Run all enhanced detectors and return unified findings + score delta."""
    ext_finds   = detect_susp_extensions(raw_text + '\n' + decoded_text)
    flag_finds  = detect_exec_flags(raw_text)
    url_finds   = detect_susp_urls(raw_text + '\n' + decoded_text)
    obf_finds   = detect_obfuscation(raw_text + '\n' + decoded_text)
    score_delta = sum(f['score'] for f in ext_finds + flag_finds + url_finds + obf_finds)
    all_mitre   = list({f['mitre'] for f in ext_finds + flag_finds + url_finds + obf_finds if f.get('mitre')})
    return {
        'susp_extensions': ext_finds,
        'exec_flags':      flag_finds,
        'susp_urls':       url_finds,
        'obfuscation':     obf_finds,
        'score_delta':     min(score_delta, 60),
        'extra_mitre':     all_mitre,
        'filename':        filename or '',
    }


def decode_ps(raw):
    layers, cur = [], raw.strip()
    # -enc UTF-16LE
    m = re.search(r'-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{20,})', cur, re.I)
    if m:
        try:
            b = base64.b64decode(m.group(1))
            out = ''.join(chr(b[i]) for i in range(0,len(b)-1,2) if b[i]<128)
            if out.strip(): layers.append({"type":"BASE64 -enc (UTF-16LE)","result":out}); cur=out
        except: pass
    # inline quoted b64
    m = re.search(r'[\'"]([A-Za-z0-9+/]{40,}={0,2})[\'"]', cur)
    if m:
        try:
            d = base64.b64decode(m.group(1)).decode('utf-8','ignore')
            if re.search(r'[\w\s(){};=]',d): layers.append({"type":"INLINE BASE64","result":d}); cur=d
        except: pass
    # FromBase64String
    m = re.search(r'[Ff]rom[Bb]ase64[Ss]tring\([\'"]([A-Za-z0-9+/=]{20,})[\'"]\)', cur)
    if m:
        try:
            d = base64.b64decode(m.group(1)).decode('utf-8','ignore')
            layers.append({"type":"FromBase64String()","result":d}); cur=d
        except: pass
    # Hex 0x
    m = re.search(r'((?:0x[0-9a-fA-F]{2},?\s*){8,})', cur)
    if m:
        try:
            h = re.sub(r'0x|[\s,]','',m.group(1))
            d = bytes.fromhex(h).decode('utf-8','ignore')
            if re.search(r'[\w\s]',d): layers.append({"type":"HEX SEQUENCE","result":d}); cur=d
        except: pass
    # Standalone blob
    m = re.search(r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{60,}={0,2})(?![A-Za-z0-9+/])', cur)
    if m:
        try:
            d = base64.b64decode(m.group(1)).decode('utf-8','ignore')
            if re.search(r'[a-zA-Z]{4}',d): layers.append({"type":"STANDALONE BASE64","result":d}); cur=d
        except: pass
    if not layers: layers.append({"type":"PLAIN TEXT","result":cur})
    return {"layers":layers,"final":cur}

def analyze_ps(text):
    lower = text.lower()
    score, inds, mitre = 0, [], []
    for r in PS_RULES:
        if any(k in lower for k in r["kw"]):
            score += r["score"]
            inds.append({"tag":r["tag"],"text":r["txt"],"mitre":r["mitre"]})
            if r["mitre"]: mitre.append(r["mitre"])
    obf = len(re.findall(r'[`+\'"]',text))
    if obf>12: score+=15; inds.append({"tag":"HIGH","text":f"Obfuscation: {obf} chars.","mitre":"T1027"})
    if len(text)>800: score+=8; inds.append({"tag":"MEDIUM","text":f"Large payload: {len(text)} chars.","mitre":""})
    return {"score":min(score,100),"indicators":inds,"mitre":list(set(mitre))}

def extract_iocs(text):
    ioc = {
        "ips":    list(set(ip for ip in re.findall(r'\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b',text) if not ip.startswith(('127.','0.','255.')))),
        "urls":   list(set(u.rstrip('.,;)') for u in re.findall(r'https?://[^\s"\'<>]{4,}',text))),
        "hashes": [],
        "emails": list(set(re.findall(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',text))),
        "cves":   list(set(re.findall(r'CVE-\d{4}-\d{4,7}',text,re.I))),
        "regkeys":list(set(re.findall(r'HK(?:LM|CU|CR|U|CC)\\[^\s"\'<>\\]{3,}',text,re.I))),
        "paths":  list(set(re.findall(r'[A-Za-z]:\\[^\s"\'<>|]{4,}',text))),
        "domains":[]
    }
    for h in re.findall(r'\b[a-fA-F0-9]{32}\b',text): ioc["hashes"].append("MD5:"+h)
    for h in re.findall(r'\b[a-fA-F0-9]{40}\b',text): ioc["hashes"].append("SHA1:"+h)
    for h in re.findall(r'\b[a-fA-F0-9]{64}\b',text): ioc["hashes"].append("SHA256:"+h)
    ioc["hashes"] = list(set(ioc["hashes"]))
    doms = re.findall(r'\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|xyz|tk|ml|top|site|click|online|pw|info|ru|cn)\b',text,re.I)
    ioc["domains"] = list(set(d.lower() for d in doms if not re.match(r'^(google|microsoft|windows|github)',d,re.I)))[:20]
    # ── Dark web / covert channel indicators ──────────────────
    darkweb = []
    for o in re.findall(r'\b[a-z2-7]{16,56}\.onion\b', text, re.I):
        darkweb.append(f"ONION:{o.lower()}")
    for t in re.findall(r'(?:https?://)?t\.me/[A-Za-z0-9_+]{3,}', text):
        darkweb.append(f"TELEGRAM:{t}")
    for p in re.findall(r'https?://(?:pastebin\.com|ghostbin\.co|hastebin\.com|rentry\.co|paste\.ee|paste\.sh|0paste\.com|justpaste\.it)/[^\s"\'<>]+', text, re.I):
        darkweb.append(f"PASTE:{p}")
    for p in re.findall(r'https?://(?:transfer\.sh|file\.io|anonfiles\.com|ufile\.io)/[^\s"\'<>]+', text, re.I):
        darkweb.append(f"ANONFILE:{p}")
    ioc["darkweb"] = list(set(darkweb))[:25]
    for k in ioc: ioc[k] = ioc[k][:25]
    return ioc

def save_scan(scan_type, name, lvl, score, summary, iocs, files_data=None, mitre_list=None):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO scans(scan_type,target_name,risk_level,risk_score,summary) VALUES(?,?,?,?,?)",
              (scan_type, name, lvl, score, json.dumps(summary)))
    scan_id = c.lastrowid
    for itype, vals in iocs.items():
        for v in vals:
            c.execute("INSERT INTO iocs(scan_id,ioc_type,value) VALUES(?,?,?)",(scan_id,itype,v))
    if files_data:
        for f in files_data:
            c.execute("INSERT INTO files(scan_id,file_path,file_ext,file_size,risk_score,encoding,entropy,decoded,indicators) VALUES(?,?,?,?,?,?,?,?,?)",
                      (scan_id,f.get("path",""),f.get("ext",""),f.get("size",0),f.get("score",0),
                       f.get("encoding","NONE"),f.get("entropy",0),f.get("decoded","")[:4000],json.dumps(f.get("indicators",[]))))
    if mitre_list:
        for t in set(mitre_list):
            name2,tac = MITRE_DB.get(t,("Unknown","Unknown"))
            c.execute("INSERT INTO mitre_hits(scan_id,technique,name,tactic) VALUES(?,?,?,?)",(scan_id,t,name2,tac))
    conn.commit(); conn.close()
    return scan_id

# ══════════════════════════════════════════════════════════
# VIRUSTOTAL (optional - works if VT_API_KEY is set)
# ══════════════════════════════════════════════════════════
def vt_lookup(hash_or_url, lookup_type="hash"):
    if not VT_API_KEY:
        return {"error":"VT_API_KEY not set","configured":False}
    try:
        import requests as req
        if lookup_type == "hash":
            resp = req.get(f"https://www.virustotal.com/api/v3/files/{hash_or_url}",
                           headers={"x-apikey":VT_API_KEY},timeout=10)
        else:
            uid = base64.urlsafe_b64encode(hash_or_url.encode()).decode().rstrip("=")
            resp = req.get(f"https://www.virustotal.com/api/v3/urls/{uid}",
                           headers={"x-apikey":VT_API_KEY},timeout=10)
        if resp.status_code == 200:
            stats = resp.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
            return {"found":True,"malicious":stats.get("malicious",0),"suspicious":stats.get("suspicious",0),
                    "harmless":stats.get("harmless",0),"total":sum(stats.values()),"configured":True}
        return {"found":False,"status":resp.status_code,"configured":True}
    except Exception as e:
        return {"error":str(e),"configured":True}

# ══════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════

@app.route('/')
def index(): return send_from_directory(FRONTEND,'index.html')

@app.route('/<path:filename>')
def static_files(filename): return send_from_directory(FRONTEND,filename)

@app.route('/api/health')
def health():
    return jsonify({
        "status":"online","version":"4.0",
        "vt_configured":bool(VT_API_KEY),
        "db":os.path.exists(DB_PATH),
        "ml_model_loaded": ML_MODEL is not None,
        "ml_accuracy": ML_METADATA.get('accuracy') if ML_METADATA else None,
        "timestamp":datetime.datetime.now().isoformat()
    })

# ── ML: Predict single URL ────────────────────────────────
@app.route('/api/ml/predict', methods=['POST'])
def ml_predict_url():
    data = request.get_json()
    url  = (data or {}).get('url','').strip()
    if not url: return jsonify({"error":"No URL"}), 400
    result = ml_predict(url)
    return jsonify(result)

# ── ML: Batch predict URLs ────────────────────────────────
@app.route('/api/ml/predict/batch', methods=['POST'])
def ml_predict_batch():
    data = request.get_json()
    urls = (data or {}).get('urls', [])
    if not urls: return jsonify({"error":"No URLs"}), 400
    results = [{"url": u, "result": ml_predict(u)} for u in urls[:50]]
    return jsonify({"predictions": results, "total": len(results)})

# ── ML: Model info ────────────────────────────────────────
@app.route('/api/ml/info')
def ml_info():
    if ML_METADATA is None:
        return jsonify({"available": False, "message": "Run train_model.py first"})
    return jsonify({"available": True, **ML_METADATA})

# ── SCAN: PowerShell (text) ───────────────────────────────
@app.route('/api/scan/ps', methods=['POST'])
def scan_ps():
    data = request.get_json()
    raw = (data or {}).get('payload','').strip()
    if not raw: return jsonify({"error":"No payload"}),400
    dec      = decode_ps(raw)
    analysis = analyze_ps(dec['final'])
    enhanced = build_enhanced_analysis(raw, dec['final'])
    iocs     = extract_iocs(raw+'\n'+dec['final'])
    score    = min(analysis['score'] + enhanced['score_delta'], 100)
    all_mitre = list(set(analysis['mitre'] + enhanced['extra_mitre']))
    lvl      = risk_level(score)
    ioc_total = sum(len(v) for v in iocs.values())
    all_inds = (analysis['indicators']
                + [{'tag':f['tag'],'text':f['text'],'mitre':f.get('mitre','')} for f in enhanced['exec_flags']]
                + [{'tag':f['tag'],'text':f['text'],'mitre':f.get('mitre','')} for f in enhanced['susp_extensions']]
                + [{'tag':f['tag'],'text':f['text'],'mitre':f.get('mitre','')} for f in enhanced['susp_urls']]
                + [{'tag':f['tag'],'text':f['text'],'mitre':f.get('mitre','')} for f in enhanced['obfuscation']])
    summary  = {"layers":len(dec['layers']),"encoding":[l['type'] for l in dec['layers']],
                "mitre":all_mitre,"ioc_count":ioc_total,
                "exec_flags":len(enhanced['exec_flags']),
                "susp_extensions":len(enhanced['susp_extensions']),
                "susp_urls":len(enhanced['susp_urls'])}
    scan_id  = save_scan('ps', raw[:60]+'…', lvl, score, summary, iocs, mitre_list=all_mitre)
    return jsonify({"scan_id":scan_id,"risk_level":lvl,"risk_score":score,
                    "layers":dec['layers'],"final":dec['final'],
                    "indicators":all_inds,"mitre":all_mitre,
                    "iocs":iocs,"summary":summary,"enhanced":enhanced})


# ── SCAN: PowerShell FILE UPLOAD ──────────────────────────
@app.route('/api/scan/ps/file', methods=['POST'])
def scan_ps_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f    = request.files['file']
    fname = f.filename or 'unknown'
    ext  = os.path.splitext(fname)[1].lower()

    # Security: only allow safe-to-read text-like extensions
    if ext not in ALLOWED_UPLOAD_EXTS:
        return jsonify({"error": f"File type '{ext}' not allowed. Supported: {', '.join(sorted(ALLOWED_UPLOAD_EXTS))}"}), 400

    raw_bytes = f.read(MAX_UPLOAD_BYTES + 1)
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        return jsonify({"error": "File too large (max 5 MB)"}), 413

    # Sanitize: decode as UTF-8 (ignore bad bytes) — never execute
    try:
        raw = raw_bytes.decode('utf-8', errors='ignore')
    except Exception:
        raw = raw_bytes.decode('latin-1', errors='ignore')

    if not raw.strip():
        return jsonify({"error": "File appears empty"}), 400

    file_size   = len(raw_bytes)
    file_hash   = hashlib.sha256(raw_bytes).hexdigest()
    file_entropy = shannon_entropy(raw[:8000])

    dec      = decode_ps(raw)
    analysis = analyze_ps(dec['final'])
    enhanced = build_enhanced_analysis(raw, dec['final'], filename=fname)
    iocs     = extract_iocs(raw+'\n'+dec['final'])

    score    = min(analysis['score'] + enhanced['score_delta'], 100)
    # Extra score boosts for dangerous file types
    if ext in ('.hta', '.jse', '.scr', '.pif'):
        score = min(score + 25, 100)
    elif ext in ('.bat', '.cmd', '.vbs', '.js'):
        score = min(score + 12, 100)
    if file_entropy > 7.0:
        score = min(score + 15, 100)
    elif file_entropy > 5.5:
        score = min(score + 8, 100)

    all_mitre = list(set(analysis['mitre'] + enhanced['extra_mitre']))
    lvl       = risk_level(score)
    ioc_total = sum(len(v) for v in iocs.values())

    # Merge all indicator types
    all_inds = (analysis['indicators']
                + [{'tag':f['tag'],'text':f['text'],'mitre':f.get('mitre','')} for f in enhanced['exec_flags']]
                + [{'tag':f['tag'],'text':f['text'],'context':f.get('context',''),'mitre':f.get('mitre','')} for f in enhanced['susp_extensions']]
                + [{'tag':f['tag'],'text':f['text'],'context':f.get('context',''),'mitre':f.get('mitre','')} for f in enhanced['susp_urls']]
                + [{'tag':f['tag'],'text':f['text'],'mitre':f.get('mitre','')} for f in enhanced['obfuscation']])

    # Determine dominant threat category
    lower = (raw+dec['final']).lower()
    if 'mimikatz' in lower or 'sekurlsa' in lower:     threat_type = 'CREDENTIAL HARVESTER'
    elif 'tcpclient' in lower or 'sockets' in lower:   threat_type = 'REVERSE SHELL'
    elif 'downloadstring' in lower or 'webclient' in lower: threat_type = 'REMOTE LOADER'
    elif 'schtasks' in lower or 'reg add' in lower:    threat_type = 'PERSISTENCE DROPPER'
    elif 'amsi' in lower:                               threat_type = 'SECURITY BYPASS'
    elif 'iex' in lower or 'invoke-expression' in lower: threat_type = 'CODE EXECUTOR'
    elif ext == '.hta':                                 threat_type = 'HTA DROPPER'
    elif ext in ('.bat', '.cmd'):                       threat_type = 'BATCH DROPPER'
    else:                                               threat_type = 'GENERAL SCRIPT'

    summary = {
        "filename": fname, "file_ext": ext, "file_size": file_size,
        "sha256": file_hash, "entropy": round(file_entropy, 3),
        "layers": len(dec['layers']), "encoding": [l['type'] for l in dec['layers']],
        "mitre": all_mitre, "ioc_count": ioc_total,
        "exec_flags": len(enhanced['exec_flags']),
        "susp_extensions": len(enhanced['susp_extensions']),
        "susp_urls": len(enhanced['susp_urls']),
        "obfuscation_hits": len(enhanced['obfuscation']),
        "threat_type": threat_type,
    }
    scan_id = save_scan('ps_file', fname, lvl, score, summary, iocs, mitre_list=all_mitre)

    return jsonify({
        "scan_id":    scan_id,
        "source":     "file",
        "filename":   fname,
        "file_ext":   ext,
        "file_size":  file_size,
        "sha256":     file_hash,
        "entropy":    round(file_entropy, 3),
        "risk_level": lvl,
        "risk_score": score,
        "threat_type": threat_type,
        "layers":     dec['layers'],
        "final":      dec['final'],
        "indicators": all_inds,
        "mitre":      all_mitre,
        "iocs":       iocs,
        "summary":    summary,
        "enhanced":   enhanced,
        # preview: first 3000 chars of raw for display
        "raw_preview": raw[:3000],
    })


# ── SCAN: URL ─────────────────────────────────────────────
@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    data = request.get_json()
    raw = (data or {}).get('url','').strip()
    if not raw: return jsonify({"error":"No URL"}),400
    url = raw if raw.startswith('http') else 'https://'+raw
    try:
        from urllib.parse import urlparse
        p = urlparse(url); host=p.hostname or ''; path=p.path or '/'; query=p.query or ''
        parts=[x for x in host.split('.') if x]
    except: host=raw; path='/'; query=''; parts=[raw]

    score=0; inds=[]
    SUSP_TLD  = {'.xyz','.tk','.ml','.ga','.cf','.gq','.pw','.top','.click','.online','.site','.buzz','.icu'}
    BRANDS    = ['paypal','amazon','microsoft','apple','google','facebook','instagram','netflix','bankof','coinbase','binance','metamask','verify','secure-','login','signin','account-','update-','billing-']
    SUSP_KW   = ['cmd=','exec=','payload','shell','invoke','bypass','run=','b64=','enc=','install','setup']
    SHORTENERS= ['bit.ly','tinyurl','t.co','goo.gl','ow.ly','is.gd','buff.ly','rb.gy']

    if re.match(r'^\d{1,3}(\.\d{1,3}){3}',host): score+=22; inds.append({"tag":"HIGH","text":"Raw IP host — avoids registered domains."})
    tld=next((t for t in SUSP_TLD if host.endswith(t)),None)
    if tld: score+=20; inds.append({"tag":"HIGH","text":f"Suspicious TLD '{tld}'."})
    for b in BRANDS:
        if b in host: score+=18; inds.append({"tag":"HIGH","text":f"Brand impersonation: '{b}' in domain."})
    if len(host)>40: score+=10; inds.append({"tag":"MEDIUM","text":f"Long domain ({len(host)} chars)."})
    if len(parts)>4: score+=10; inds.append({"tag":"MEDIUM","text":f"{len(parts)-2} subdomain levels."})
    if not url.startswith('https'): score+=8; inds.append({"tag":"MEDIUM","text":"No HTTPS."})
    if any(s in host for s in SHORTENERS): score+=12; inds.append({"tag":"MEDIUM","text":"URL shortener detected."})
    for k in SUSP_KW:
        if k in url.lower(): score+=14; inds.append({"tag":"HIGH","text":f"Suspicious param '{k}'."})
    if len(query)>80: score+=8; inds.append({"tag":"MEDIUM","text":f"Long query string ({len(query)} chars)."})
    if not inds: inds.append({"tag":"INFO","text":"No phishing indicators detected."})
    score=min(score,100); lvl=risk_level(score)
    vt = vt_lookup(url,"url") if VT_API_KEY else {"configured":False}
    ml = ml_predict(url)
    iocs = extract_iocs(url)
    summary = {"hostname":host,"path":path,"subdomain_depth":max(0,len(parts)-2),"vt":vt,"ml_prediction":ml.get("prediction")}
    scan_id = save_scan('url', url[:80], lvl, score, summary, iocs)
    return jsonify({"scan_id":scan_id,"risk_level":lvl,"risk_score":score,"hostname":host,
                    "path":path,"query":query,"subdomain_depth":max(0,len(parts)-2),
                    "protocol":"HTTPS" if url.startswith("https") else "HTTP",
                    "indicators":inds,"iocs":iocs,"virustotal":vt,"ml":ml})

# ── SCAN: ZIP ─────────────────────────────────────────────
@app.route('/api/scan/zip', methods=['POST'])
def scan_zip():
    if 'file' not in request.files: return jsonify({"error":"No file"}),400
    f = request.files['file']
    if not f.filename.endswith('.zip'): return jsonify({"error":"ZIP only"}),400
    raw = f.read()
    zip_hash = hashlib.sha256(raw).hexdigest()
    try: zf = zipfile.ZipFile(io.BytesIO(raw))
    except Exception as e: return jsonify({"error":str(e)}),400

    files_r=[]; all_text=''; max_score=0; threats=scripts=encoded=execs=0
    archive_inds=[]; zip_mitre=set()

    for info in zf.infolist():
        if info.is_dir(): continue
        try: content=zf.read(info.filename).decode('utf-8','ignore')
        except: content='[binary]'
        path=info.filename; ext='.'+path.split('.')[-1].lower() if '.' in path else ''
        file_score=0; file_inds=[]; decoded=content; enc_type='NONE'; fmitre=[]
        all_text+=content+'\n'
        if ext in SCRIPTS: scripts+=1
        if ext in DANGEROUS: execs+=1; file_score+=30
        if content!='[binary]':
            dec=decode_ps(content); decoded=dec['final']
            was_enc=len(dec['layers'])>1 or dec['layers'][0]['type']!='PLAIN TEXT'
            if was_enc:
                enc_type=' → '.join(l['type'] for l in dec['layers'])
                encoded+=1; file_score+=15
                file_inds.append({"tag":"ENCODED","text":f"Encoded: {enc_type}","mitre":"T1027"})
            psa=analyze_ps(decoded)
            if psa['score']>0:
                file_score+=psa['score']//(3 if ext in SCRIPTS else 2)
                file_inds.extend(psa['indicators']); fmitre.extend(psa['mitre']); zip_mitre.update(psa['mitre'])
        if path.count('.')>1 and ext in DANGEROUS:
            file_score+=20; file_inds.append({"tag":"CRITICAL","text":"Double extension.","mitre":"T1027"})
        if re.search(r'invoice|payment|urgent|password|credentials|update|install|verify',path,re.I):
            file_score+=12; file_inds.append({"tag":"HIGH","text":f"Social engineering filename."})
        if ext in DOCUMENTS: file_score+=15; file_inds.append({"tag":"MEDIUM","text":"Macro-enabled document."})
        ent=shannon_entropy(content[:8000])
        if ent>7: file_score+=15; file_inds.append({"tag":"HIGH","text":f"Very high entropy ({ent:.2f}).","mitre":"T1027"})
        elif ent>5.5: file_score+=8; file_inds.append({"tag":"MEDIUM","text":f"High entropy ({ent:.2f}).","mitre":"T1027"})
        file_score=min(file_score,100); max_score=max(max_score,file_score)
        if file_score>=50 or ext in DANGEROUS: threats+=1
        size=info.file_size
        files_r.append({"path":path,"ext":ext,"size":size,"score":file_score,
                         "encoding":enc_type,"entropy":round(ent,3),
                         "decoded":decoded[:2000],"indicators":file_inds,"mitre":list(set(fmitre))})

    danger_ct=sum(1 for x in files_r if x['ext'] in DANGEROUS)
    if danger_ct: archive_inds.append({"tag":"CRITICAL","text":f"{danger_ct} executable(s) bypass email filters.","mitre":"T1027"})
    if scripts: archive_inds.append({"tag":"HIGH","text":f"{scripts} script(s) detected.","mitre":"T1059.001"})
    if encoded: archive_inds.append({"tag":"HIGH","text":f"{encoded} encoded payload(s).","mitre":"T1027"})
    if not archive_inds: archive_inds.append({"tag":"INFO","text":"No archive-level threats."})

    iocs=extract_iocs(all_text)
    ioc_total=sum(len(v) for v in iocs.values())
    final_score=min(max_score,100); lvl=risk_level(final_score)
    summary={"total_files":len(files_r),"threats":threats,"scripts":scripts,
             "encoded":encoded,"executables":execs,"ioc_count":ioc_total,
             "zip_sha256":zip_hash,"mitre":list(zip_mitre)}
    scan_id=save_scan('zip',f.filename,lvl,final_score,summary,iocs,
                      files_data=files_r,mitre_list=list(zip_mitre))
    return jsonify({"scan_id":scan_id,"risk_level":lvl,"risk_score":final_score,
                    "zip_sha256":zip_hash,
                    "stats":{"total":len(files_r),"threats":threats,"scripts":scripts,
                             "encoded":encoded,"executables":execs,"iocs":ioc_total},
                    "files":files_r,"archive_indicators":archive_inds,
                    "iocs":iocs,"mitre":list(zip_mitre)})

# ── IOC EXTRACT ───────────────────────────────────────────
@app.route('/api/extract/iocs', methods=['POST'])
def api_extract_iocs():
    data = request.get_json()
    text = (data or {}).get('text','')
    if not text: return jsonify({"error":"No text"}),400
    iocs = extract_iocs(text)
    return jsonify({"iocs":iocs,"total":sum(len(v) for v in iocs.values())})

# ── HISTORY ───────────────────────────────────────────────
@app.route('/api/history')
def history():
    limit=int(request.args.get('limit',50))
    stype=request.args.get('type',None)
    conn=get_db()
    if stype:
        rows=conn.execute("SELECT id,scan_type,target_name,risk_level,risk_score,created_at FROM scans WHERE scan_type=? ORDER BY id DESC LIMIT ?",(stype,limit)).fetchall()
    else:
        rows=conn.execute("SELECT id,scan_type,target_name,risk_level,risk_score,created_at FROM scans ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/history/<int:scan_id>')
def history_detail(scan_id):
    conn=get_db()
    scan=conn.execute("SELECT * FROM scans WHERE id=?",(scan_id,)).fetchone()
    if not scan: conn.close(); return jsonify({"error":"Not found"}),404
    iocs=conn.execute("SELECT ioc_type,value FROM iocs WHERE scan_id=?",(scan_id,)).fetchall()
    files=conn.execute("SELECT * FROM files WHERE scan_id=?",(scan_id,)).fetchall()
    mitre=conn.execute("SELECT technique,name,tactic FROM mitre_hits WHERE scan_id=?",(scan_id,)).fetchall()
    conn.close()
    return jsonify({"scan":dict(scan),"iocs":[dict(r) for r in iocs],
                    "files":[dict(r) for r in files],"mitre":[dict(r) for r in mitre]})

@app.route('/api/history/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    conn=get_db()
    for tbl in ['iocs','files','mitre_hits']:
        conn.execute(f"DELETE FROM {tbl} WHERE scan_id=?",(scan_id,))
    conn.execute("DELETE FROM scans WHERE id=?",(scan_id,))
    conn.commit(); conn.close()
    return jsonify({"deleted":scan_id})

# ── STATS (dashboard) ─────────────────────────────────────
@app.route('/api/stats')
def stats():
    conn=get_db()
    total   =conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    high    =conn.execute("SELECT COUNT(*) FROM scans WHERE risk_level='HIGH'").fetchone()[0]
    medium  =conn.execute("SELECT COUNT(*) FROM scans WHERE risk_level='MEDIUM'").fetchone()[0]
    low     =conn.execute("SELECT COUNT(*) FROM scans WHERE risk_level='LOW'").fetchone()[0]
    ioc_cnt =conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    by_type =conn.execute("SELECT scan_type,COUNT(*) cnt FROM scans GROUP BY scan_type").fetchall()
    top_mit =conn.execute("SELECT technique,name,COUNT(*) cnt FROM mitre_hits GROUP BY technique ORDER BY cnt DESC LIMIT 8").fetchall()
    recent  =conn.execute("SELECT id,scan_type,target_name,risk_level,risk_score,created_at FROM scans ORDER BY id DESC LIMIT 10").fetchall()
    daily   =conn.execute("SELECT DATE(created_at) d,COUNT(*) cnt FROM scans WHERE created_at >= DATE('now','-7 days') GROUP BY d ORDER BY d").fetchall()
    conn.close()
    return jsonify({"total_scans":total,"by_risk":{"HIGH":high,"MEDIUM":medium,"LOW":low},
                    "total_iocs":ioc_cnt,"by_type":[dict(r) for r in by_type],
                    "top_mitre":[dict(r) for r in top_mit],
                    "recent_scans":[dict(r) for r in recent],
                    "daily_scans":[dict(r) for r in daily]})

# ── SEARCH ────────────────────────────────────────────────
@app.route('/api/search/ioc')
def search_ioc():
    q=request.args.get('q','').strip()
    if not q: return jsonify({"error":"No query"}),400
    conn=get_db()
    rows=conn.execute("SELECT i.ioc_type,i.value,s.scan_type,s.target_name,s.risk_level,s.created_at,s.id scan_id FROM iocs i JOIN scans s ON i.scan_id=s.id WHERE i.value LIKE ? LIMIT 50",(f'%{q}%',)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ══════════════════════════════════════════════════════════
# EML SCANNER — Email / .eml file analysis engine
# ══════════════════════════════════════════════════════════
import email as email_lib
from email import policy as email_policy
from email.header import decode_header as decode_hdr

SPOOFED_TLDS = {'.xyz','.tk','.ml','.ga','.cf','.gq','.pw','.top','.click','.online','.site','.buzz','.icu','.fun'}
BRAND_NAMES  = ['paypal','amazon','microsoft','apple','google','facebook','instagram',
                'netflix','coinbase','binance','bankof','hsbc','wellsfargo','chase',
                'linkedin','twitter','dropbox','spotify','steam','docusign','fedex','dhl']
URGENCY_KW   = ['urgent','immediately','verify','suspended','account locked','limited time',
                'click here','confirm your','update your','unusual activity','security alert',
                'password expired','your account','action required','within 24','within 48']

def decode_mime_words(s):
    """Decode encoded email header words like =?utf-8?..."""
    if not s: return ''
    parts = []
    for byt, enc in decode_hdr(str(s)):
        if isinstance(byt, bytes):
            parts.append(byt.decode(enc or 'utf-8', errors='ignore'))
        else:
            parts.append(str(byt))
    return ' '.join(parts)

def analyze_headers(msg):
    """Check email headers for spoofing, SPF/DKIM/DMARC, mismatch."""
    score = 0
    flags = []

    from_raw  = decode_mime_words(msg.get('From',''))
    reply_to  = decode_mime_words(msg.get('Reply-To',''))
    ret_path  = decode_mime_words(msg.get('Return-Path',''))
    subj      = decode_mime_words(msg.get('Subject',''))
    auth_res  = msg.get('Authentication-Results','').lower()
    recv      = ' '.join(msg.get_all('Received') or [])

    # Extract email address from From field
    from_email = re.search(r'<([^>]+)>', from_raw)
    from_email = from_email.group(1).lower() if from_email else from_raw.lower()
    from_domain = from_email.split('@')[-1] if '@' in from_email else ''

    # SPF check
    if 'spf=fail' in auth_res or 'spf=softfail' in auth_res:
        score += 25; flags.append({'tag':'CRITICAL','text':'SPF authentication failed — sender domain could not be verified.','mitre':'T1566.001'})
    elif 'spf=pass' not in auth_res and auth_res:
        score += 10; flags.append({'tag':'MEDIUM','text':'SPF result missing or neutral — unverified sender.','mitre':'T1566.001'})

    # DKIM check
    if 'dkim=fail' in auth_res:
        score += 20; flags.append({'tag':'HIGH','text':'DKIM signature verification failed — email may have been tampered.','mitre':'T1566.001'})
    elif 'dkim=none' in auth_res:
        score += 8; flags.append({'tag':'MEDIUM','text':'No DKIM signature present.','mitre':'T1566.001'})

    # DMARC check
    if 'dmarc=fail' in auth_res:
        score += 22; flags.append({'tag':'CRITICAL','text':'DMARC policy check failed — domain impersonation likely.','mitre':'T1566.001'})

    # Reply-To mismatch (classic phishing trick)
    if reply_to and reply_to.lower() != from_raw.lower():
        rt_email = re.search(r'<([^>]+)>', reply_to)
        rt_email = rt_email.group(1).lower() if rt_email else reply_to.lower()
        rt_domain = rt_email.split('@')[-1] if '@' in rt_email else ''
        if rt_domain and from_domain and rt_domain != from_domain:
            score += 30; flags.append({'tag':'CRITICAL','text':f'Reply-To domain ({rt_domain}) differs from From domain ({from_domain}) — classic phishing redirect.','mitre':'T1566.001'})

    # Suspicious sender TLD
    if from_domain:
        tld = '.' + from_domain.split('.')[-1] if '.' in from_domain else ''
        if tld in SPOOFED_TLDS:
            score += 20; flags.append({'tag':'HIGH','text':f'Suspicious sender TLD ({tld}) — commonly used in phishing.','mitre':'T1566.001'})

    # Brand impersonation in From display name but different domain
    for brand in BRAND_NAMES:
        if brand in from_raw.lower() and brand not in from_domain:
            score += 25; flags.append({'tag':'CRITICAL','text':f'Display name impersonates "{brand}" but sender domain is "{from_domain}".','mitre':'T1566.001'})
            break

    # Urgency in subject
    subj_lower = subj.lower()
    matched_urgency = [k for k in URGENCY_KW if k in subj_lower]
    if len(matched_urgency) >= 2:
        score += 18; flags.append({'tag':'HIGH','text':f'Subject uses urgency language: {", ".join(matched_urgency[:3])}.','mitre':'T1566.001'})
    elif matched_urgency:
        score += 8; flags.append({'tag':'MEDIUM','text':f'Subject contains urgency keyword: "{matched_urgency[0]}".','mitre':'T1566.001'})

    # No received headers (locally crafted or spoofed)
    received_all = msg.get_all('Received') or []
    if len(received_all) < 2:
        score += 12; flags.append({'tag':'MEDIUM','text':f'Only {len(received_all)} Received header(s) — email may be locally crafted.','mitre':'T1566.001'})

    if not flags:
        flags.append({'tag':'INFO','text':'No suspicious header patterns detected.','mitre':''})

    return {
        'score': min(score, 100),
        'flags': flags,
        'metadata': {
            'from':       from_raw,
            'from_email': from_email,
            'from_domain':from_domain,
            'reply_to':   reply_to or '(none)',
            'return_path':ret_path or '(none)',
            'subject':    subj or '(no subject)',
            'auth_results': msg.get('Authentication-Results','(not present)'),
            'message_id': msg.get('Message-ID','(none)'),
            'received_hops': len(received_all),
            'date': msg.get('Date','(unknown)'),
        }
    }

def analyze_body_text(text):
    """Scan email body for urgency, credential harvesting, and extract URLs."""
    score = 0
    flags = []
    text_lower = text.lower()

    # Credential harvesting keywords
    cred_kw = ['enter your password','verify your identity','confirm your account',
                'update billing','enter your credentials','sign in now','click to verify',
                'your account will be','we detected unusual','login to confirm']
    matched = [k for k in cred_kw if k in text_lower]
    if matched:
        score += 20 * min(len(matched), 3)
        flags.append({'tag':'HIGH','text':f'Credential harvesting language detected: {len(matched)} pattern(s).','mitre':'T1566.001'})

    # Count urgency words in body
    urg_matches = [k for k in URGENCY_KW if k in text_lower]
    if len(urg_matches) >= 3:
        score += 15; flags.append({'tag':'HIGH','text':f'Body contains {len(urg_matches)} urgency keywords.','mitre':'T1566.001'})
    elif urg_matches:
        score += 5; flags.append({'tag':'MEDIUM','text':f'Body contains urgency keyword: "{urg_matches[0]}".','mitre':'T1566.001'})

    # Extract URLs from body
    urls = list(set(u.rstrip('.,;)>') for u in re.findall(r'https?://[^\s"\'<>\)]{6,}', text)))
    if len(urls) > 5:
        score += 10; flags.append({'tag':'MEDIUM','text':f'{len(urls)} URLs found in body — higher than average.','mitre':'T1566.001'})

    return {'score': min(score, 100), 'flags': flags, 'urls': urls[:30]}

def get_body_text(msg):
    """Extract plain text and HTML body from email."""
    plain, html = '', ''
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get('Content-Disposition',''))
            if 'attachment' in cd: continue
            charset = part.get_content_charset() or 'utf-8'
            try:
                payload = part.get_payload(decode=True)
                if payload is None: continue
                decoded = payload.decode(charset, errors='ignore')
                if ct == 'text/plain': plain += decoded
                elif ct == 'text/html': html += decoded
            except: pass
    else:
        charset = msg.get_content_charset() or 'utf-8'
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                plain = payload.decode(charset, errors='ignore')
        except: pass
    # Strip HTML tags for text
    if html and not plain:
        plain = re.sub(r'<[^>]+>', ' ', html)
        plain = re.sub(r'&nbsp;',' ', plain)
        plain = re.sub(r'\s+',' ', plain).strip()
    return plain, html

def get_attachments(msg):
    """Extract attachments from email message."""
    attachments = []
    for part in msg.walk():
        cd  = str(part.get('Content-Disposition',''))
        ct  = part.get_content_type()
        fn  = part.get_filename()
        if fn:
            fn = decode_mime_words(fn)
        if 'attachment' in cd or fn:
            try:
                payload = part.get_payload(decode=True)
                if payload is None: continue
                attachments.append({
                    'filename': fn or 'attachment',
                    'content_type': ct,
                    'size': len(payload),
                    'data': payload,
                    'ext': ('.' + fn.split('.')[-1].lower()) if fn and '.' in fn else ''
                })
            except: pass
    return attachments

@app.route('/api/scan/eml', methods=['POST'])
def scan_eml():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    f = request.files['file']
    if not (f.filename.lower().endswith('.eml') or f.filename.lower().endswith('.msg')):
        return jsonify({'error': 'Only .eml files supported'}), 400

    raw_bytes = f.read()
    eml_hash  = hashlib.sha256(raw_bytes).hexdigest()

    # Parse email
    try:
        msg = email_lib.message_from_bytes(raw_bytes, policy=email_policy.compat32)
    except Exception as e:
        return jsonify({'error': f'Failed to parse email: {e}'}), 400

    # ── 1. HEADER ANALYSIS ───────────────────────────────
    header_result = analyze_headers(msg)

    # ── 2. BODY ANALYSIS ─────────────────────────────────
    plain_text, html_body = get_body_text(msg)
    body_result  = analyze_body_text(plain_text)
    all_text     = plain_text

    # ── 3. URL ANALYSIS (run each body URL through scanner) ──
    url_results = []
    for url in body_result['urls'][:15]:
        try:
            # reuse existing URL scan logic inline
            from urllib.parse import urlparse as _up
            p = _up(url if url.startswith('http') else 'https://'+url)
            host  = p.hostname or ''
            parts = [x for x in host.split('.') if x]
            tld   = '.' + parts[-1] if parts else ''
            u_score = 0; u_inds = []
            SUSP_TLD2 = {'.xyz','.tk','.ml','.ga','.cf','.gq','.pw','.top','.click','.online','.site','.buzz','.icu'}
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}', host): u_score += 22; u_inds.append('Raw IP host')
            if tld in SUSP_TLD2: u_score += 20; u_inds.append(f'Suspicious TLD {tld}')
            for b in BRAND_NAMES:
                if b in host: u_score += 18; u_inds.append(f'Brand impersonation: {b}'); break
            if len(host) > 40: u_score += 10; u_inds.append('Long domain')
            if not url.startswith('https'): u_score += 8; u_inds.append('No HTTPS')
            ml = ml_predict(url)
            url_results.append({
                'url':      url,
                'domain':   host,
                'score':    min(u_score, 100),
                'risk':     risk_level(min(u_score,100)),
                'indicators': u_inds,
                'ml':       ml,
            })
        except: pass

    # ── 4. ATTACHMENT ANALYSIS ───────────────────────────
    attachments_result = []
    attach_score = 0
    all_attach_mitre = []

    for att in get_attachments(msg):
        ext  = att['ext']
        fn   = att['filename']
        data = att['data']
        size = att['size']
        a_score = 0; a_flags = []; a_decoded = ''; a_enc = 'NONE'; a_ent = 0.0; a_mitre = []

        # Classify by extension
        if ext in DANGEROUS:
            a_score += 35; a_flags.append({'tag':'CRITICAL','text':f'Dangerous executable attachment: {ext}','mitre':'T1566.001'})
        elif ext in SCRIPTS:
            a_score += 20; a_flags.append({'tag':'HIGH','text':f'Script file attached: {ext}','mitre':'T1059.001'})
        elif ext in DOCUMENTS:
            a_score += 15; a_flags.append({'tag':'MEDIUM','text':f'Macro-capable document: {ext}','mitre':'T1566.001'})
        elif ext in ARCHIVES:
            a_score += 10; a_flags.append({'tag':'MEDIUM','text':'Archive attachment — may contain nested payload.','mitre':'T1027'})

        # Social engineering filename
        if re.search(r'invoice|payment|urgent|password|credentials|update|verify|receipt|security|report|account|login|document|contract|statement',fn,re.I):
            a_score += 15; a_flags.append({'tag':'HIGH','text':f'Social engineering filename: "{fn}"','mitre':'T1566.001'})

        # Double extension
        if fn.count('.') > 1 and ext in DANGEROUS:
            a_score += 20; a_flags.append({'tag':'CRITICAL','text':f'Double extension detected: "{fn}"','mitre':'T1027'})

        # Try to decode text content
        try:
            content = data.decode('utf-8', errors='ignore')
        except:
            content = '[binary]'

        # PS decode if script
        if ext in ('.ps1','.psm1','.psd1') and content != '[binary]':
            dec = decode_ps(content)
            a_decoded = dec['final']
            was_enc   = len(dec['layers']) > 1 or dec['layers'][0]['type'] != 'PLAIN TEXT'
            if was_enc:
                a_enc = ' → '.join(l['type'] for l in dec['layers'])
                a_score += 15; a_flags.append({'tag':'HIGH','text':f'Encoded PS: {a_enc}','mitre':'T1027'})
            ps_a = analyze_ps(dec['final'])
            a_score += ps_a['score'] // 2
            a_flags.extend(ps_a['indicators'])
            a_mitre.extend(ps_a['mitre'])
        else:
            a_decoded = content[:2000]

        # Entropy
        a_ent = shannon_entropy(content[:8000])
        if a_ent > 7:   a_score += 15; a_flags.append({'tag':'HIGH','text':f'Very high entropy ({a_ent:.2f}) — packed/encrypted.','mitre':'T1027'})
        elif a_ent > 5.5: a_score += 8; a_flags.append({'tag':'MEDIUM','text':f'High entropy ({a_ent:.2f}).','mitre':'T1027'})

        all_text += '\n' + content
        a_score = min(a_score, 100)
        attach_score = max(attach_score, a_score)
        all_attach_mitre.extend(a_mitre)
        attachments_result.append({
            'filename':   fn,
            'ext':        ext,
            'size':       size,
            'score':      a_score,
            'risk':       risk_level(a_score),
            'encoding':   a_enc,
            'entropy':    round(a_ent, 3),
            'decoded':    a_decoded[:1500],
            'indicators': a_flags,
            'mitre':      list(set(a_mitre)),
        })

    # ── 5. IOC EXTRACTION ────────────────────────────────
    iocs = extract_iocs(all_text)
    # Also add body URLs to IOC list
    for u in body_result['urls']:
        if u not in iocs['urls']: iocs['urls'].append(u)
    iocs['urls'] = list(set(iocs['urls']))[:25]

    # ── 6. COMPOSITE RISK SCORE ──────────────────────────
    # ── Max-biased composite formula ─────────────────────────────────────────
    # Pure weighted average dilutes strong individual signals (e.g. a header
    # score of 85 contributes only 34 pts at 40% weight).  Instead we blend:
    #   60% driven by the WORST single component (fail-fast security posture)
    #   40% traditional weighted average (breadth of signals)
    _url_max   = max((r['score'] for r in url_results), default=0)
    _components = [header_result['score'], body_result['score'], _url_max, attach_score]
    _weighted   = (_components[0]*0.40 + _components[1]*0.25 +
                   _components[2]*0.20 + _components[3]*0.15)
    _max_comp   = max(_components)
    final_score = int(round(min(_max_comp * 0.60 + _weighted * 0.40, 100)))
    lvl = eml_risk_level(final_score)

    all_mitre = list(set(all_attach_mitre + ['T1566.001'] if header_result['flags'][0]['tag'] != 'INFO' else all_attach_mitre))

    summary = {
        'subject':          header_result['metadata']['subject'],
        'from':             header_result['metadata']['from'],
        'header_score':     header_result['score'],
        'body_score':       body_result['score'],
        'urls_found':       len(body_result['urls']),
        'attachments':      len(attachments_result),
        'ioc_count':        sum(len(v) for v in iocs.values()),
        'eml_sha256':       eml_hash,
        'mitre':            all_mitre,
    }

    scan_id = save_scan('eml', f.filename, lvl, final_score, summary, iocs,
                        mitre_list=all_mitre)

    return jsonify({
        'scan_id':       scan_id,
        'risk_level':    lvl,
        'risk_score':    final_score,
        'eml_sha256':    eml_hash,
        'headers':       header_result,
        'body': {
            'score':     body_result['score'],
            'flags':     body_result['flags'],
            'url_count': len(body_result['urls']),
            'preview':   plain_text[:600],
        },
        'urls':          url_results,
        'attachments':   attachments_result,
        'iocs':          iocs,
        'mitre':         all_mitre,
        'summary':       summary,
    })

# ══════════════════════════════════════════════════════════
# FEATURE 1: RAW EMAIL HEADER ANALYZER
# Accepts pasted raw headers (not a .eml file)
# ══════════════════════════════════════════════════════════
@app.route('/api/scan/headers', methods=['POST'])
def scan_headers_raw():
    data    = request.get_json()
    raw     = (data or {}).get('headers', '').strip()
    if not raw:
        return jsonify({"error": "No headers provided"}), 400

    # Wrap raw headers into a parseable message
    try:
        msg = email_lib.message_from_string(raw + "\n\n", policy=email_policy.compat32)
    except Exception as e:
        return jsonify({"error": f"Parse failed: {e}"}), 400

    result = analyze_headers(msg)

    # ── Received chain — extract IPs and hops ─────────────
    received_all = msg.get_all('Received') or []
    received_chain = []
    for r_hdr in received_all:
        ips = re.findall(r'\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b', r_hdr)
        public_ips = [ip for ip in ips if not re.match(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)', ip)]
        by_m   = re.search(r'\bby\s+([^\s;(]+)',   r_hdr, re.I)
        from_m = re.search(r'\bfrom\s+([^\s(]+)',  r_hdr, re.I)
        with_m = re.search(r'\bwith\s+([^\s;]+)',  r_hdr, re.I)
        date_m = re.search(r';\s*(.+)$', r_hdr.strip())
        received_chain.append({
            'raw':       r_hdr[:300],
            'ips':       public_ips,
            'by':        by_m.group(1)   if by_m   else '',
            'from_host': from_m.group(1) if from_m else '',
            'protocol':  with_m.group(1) if with_m else '',
            'date':      date_m.group(1).strip() if date_m else '',
        })

    # Originating IP = last Received header (first external hop)
    originating_ip = ''
    for hop in reversed(received_chain):
        if hop['ips']:
            originating_ip = hop['ips'][0]
            break

    # ── AbuseIPDB on originating IP ───────────────────────
    abuse_result = None
    if originating_ip and ABUSE_API_KEY:
        try:
            import requests as req
            ar = req.get('https://api.abuseipdb.com/api/v2/check',
                         params={'ipAddress': originating_ip, 'maxAgeInDays': 90},
                         headers={'Key': ABUSE_API_KEY, 'Accept': 'application/json'}, timeout=6)
            if ar.status_code == 200:
                ad = ar.json().get('data', {})
                abuse_result = {
                    'abuse_confidence': ad.get('abuseConfidenceScore', 0),
                    'country':          ad.get('countryCode', ''),
                    'isp':              ad.get('isp', ''),
                    'total_reports':    ad.get('totalReports', 0),
                }
        except: pass

    iocs  = extract_iocs(raw)
    score = result['score']
    lvl   = risk_level(score)
    summary = {
        'from':           result['metadata']['from'],
        'subject':        result['metadata']['subject'],
        'originating_ip': originating_ip,
        'received_hops':  len(received_all),
    }
    scan_id = save_scan('headers', (result['metadata']['from'] or 'Raw Headers')[:80],
                        lvl, score, summary, iocs)
    return jsonify({
        'scan_id':        scan_id,
        'risk_level':     lvl,
        'risk_score':     score,
        'flags':          result['flags'],
        'metadata':       result['metadata'],
        'received_chain': received_chain,
        'originating_ip': originating_ip,
        'abuse_check':    abuse_result,
        'iocs':           iocs,
    })


# ══════════════════════════════════════════════════════════
# FEATURE 2: DOMAIN WHOIS + AGE CHECK  (via RDAP — no key)
# ══════════════════════════════════════════════════════════
@app.route('/api/whois', methods=['POST'])
def whois_check():
    data   = request.get_json()
    domain = (data or {}).get('domain', '').strip().lower()
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    # Normalise — strip protocol and path
    domain = re.sub(r'^https?://', '', domain).split('/')[0].strip()
    # Strip leading www.
    if domain.startswith('www.'):
        domain = domain[4:]

    try:
        import requests as req
        resp = req.get(f'https://rdap.org/domain/{domain}',
                       timeout=10, headers={'Accept': 'application/json'})
        if resp.status_code != 200:
            # Try IANA RDAP bootstrap as fallback
            resp = req.get(f'https://rdap.iana.org/domain/{domain}',
                           timeout=10, headers={'Accept': 'application/json'})
        if resp.status_code != 200:
            return jsonify({'domain': domain, 'found': False,
                            'error': f'RDAP lookup failed (HTTP {resp.status_code})'}), 200

        rdap = resp.json()

        # ── Events: registration / expiry / update ────────
        reg_date = exp_date = updated = None
        for ev in rdap.get('events', []):
            action = ev.get('eventAction','').lower()
            dstr   = ev.get('eventDate','')
            if 'registration' in action:  reg_date = dstr
            elif 'expir' in action:       exp_date = dstr
            elif 'last changed' in action or 'updated' in action: updated = dstr

        # ── Domain age calculation ─────────────────────────
        age_days = None; age_flag = None
        if reg_date:
            try:
                from datetime import datetime, timezone
                dt = datetime.fromisoformat(reg_date.replace('Z', '+00:00'))
                age_days = (datetime.now(timezone.utc) - dt).days
                if   age_days < 30:  age_flag = {'level':'CRITICAL','msg':f'Domain only {age_days} day(s) old — very high phishing risk!'}
                elif age_days < 180: age_flag = {'level':'MEDIUM',  'msg':f'Domain is {age_days} days old — relatively new.'}
                else:                age_flag = {'level':'OK',      'msg':f'Domain is {age_days} days old — established.'}
            except: pass

        # ── Registrar ─────────────────────────────────────
        registrar = ''
        for entity in rdap.get('entities', []):
            if 'registrar' in entity.get('roles', []):
                vc = entity.get('vcardArray', [])
                if vc and len(vc) > 1:
                    for item in vc[1]:
                        if item[0] == 'fn': registrar = item[3]; break
                if registrar: break

        # ── Nameservers ───────────────────────────────────
        nameservers = [ns.get('ldhName','') for ns in rdap.get('nameservers', [])]

        # ── Status flags ──────────────────────────────────
        status = rdap.get('status', [])

        return jsonify({
            'domain':            domain,
            'found':             True,
            'registration_date': reg_date,
            'expiration_date':   exp_date,
            'last_updated':      updated,
            'age_days':          age_days,
            'age_flag':          age_flag,
            'registrar':         registrar,
            'nameservers':       nameservers[:8],
            'status':            status[:6],
        })

    except Exception as e:
        return jsonify({'domain': domain, 'found': False, 'error': str(e)}), 200


# ══════════════════════════════════════════════════════════
# FEATURE 3: FULL VIRUSTOTAL HASH LOOKUP
# ══════════════════════════════════════════════════════════
@app.route('/api/vt/hash', methods=['POST'])
def vt_hash_full():
    data     = request.get_json()
    hash_val = (data or {}).get('hash', '').strip().lower()
    if not hash_val:
        return jsonify({"error": "No hash provided"}), 400
    if not re.match(r'^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$', hash_val):
        return jsonify({"error": "Invalid hash. Provide MD5 (32 chars), SHA1 (40), or SHA256 (64)."}), 400
    if not VT_API_KEY:
        return jsonify({"error": "VT_API_KEY not set. Run:  export VT_API_KEY=your_key",
                        "configured": False}), 200

    # ── Check 1-hour cache ────────────────────────────────
    conn = get_db()
    cached = conn.execute("SELECT result,cached_at FROM vt_cache WHERE hash=?",
                          (hash_val,)).fetchone()
    if cached:
        age_sec = (datetime.datetime.now() -
                   datetime.datetime.fromisoformat(cached['cached_at'])).total_seconds()
        if age_sec < 3600:
            conn.close()
            return jsonify({**json.loads(cached['result']), 'cached': True})
    conn.close()

    try:
        import requests as req
        resp = req.get(f"https://www.virustotal.com/api/v3/files/{hash_val}",
                       headers={"x-apikey": VT_API_KEY}, timeout=15)
        if resp.status_code == 404:
            return jsonify({"found": False, "hash": hash_val, "configured": True, "cached": False})
        if resp.status_code != 200:
            return jsonify({"error": f"VT API returned {resp.status_code}", "configured": True}), 200

        d     = resp.json().get('data', {})
        attrs = d.get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        raw_results = attrs.get('last_analysis_results', {})

        # Top detections (malicious + suspicious only)
        detections = [
            {'engine':   eng,
             'category': res.get('category'),
             'result':   res.get('result', '')}
            for eng, res in raw_results.items()
            if res.get('category') in ('malicious', 'suspicious')
        ]
        detections.sort(key=lambda x: (x['category'] != 'malicious', x['engine']))

        hash_type = 'MD5' if len(hash_val)==32 else 'SHA1' if len(hash_val)==40 else 'SHA256'
        mal       = stats.get('malicious', 0)
        total_eng = sum(stats.values()) or 1
        verdict   = 'MALICIOUS' if mal >= 5 else 'SUSPICIOUS' if mal >= 1 else 'CLEAN'

        result_obj = {
            'found':            True,
            'configured':       True,
            'cached':           False,
            'hash':             hash_val,
            'hash_type':        hash_type,
            'verdict':          verdict,
            'name':             attrs.get('meaningful_name') or attrs.get('name', ''),
            'type_description': attrs.get('type_description', ''),
            'size':             attrs.get('size', 0),
            'stats': {
                'malicious':  mal,
                'suspicious': stats.get('suspicious', 0),
                'harmless':   stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'total':      total_eng,
            },
            'detection_rate':  round(mal / total_eng * 100, 1),
            'detections':       detections[:25],
            'tags':             attrs.get('tags', [])[:10],
            'first_seen':       attrs.get('first_submission_date', ''),
            'last_analysis':    attrs.get('last_analysis_date', ''),
            'times_submitted':  attrs.get('times_submitted', 0),
            'reputation':       attrs.get('reputation', 0),
        }

        # Cache it
        conn = get_db()
        conn.execute("INSERT OR REPLACE INTO vt_cache(hash,result,cached_at) VALUES(?,?,?)",
                     (hash_val, json.dumps(result_obj), datetime.datetime.now().isoformat()))
        conn.commit(); conn.close()
        return jsonify(result_obj)

    except Exception as e:
        return jsonify({"error": str(e), "configured": True}), 200


if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════════════════════╗
║     MINI THREAT ANALYZER v5 BACKEND — RUNNING           ║
║     Open: http://localhost:5000                         ║
╚══════════════════════════════════════════════════════════╝
  API Routes:
    POST /api/scan/zip        Scan ZIP file
    POST /api/scan/ps         Decode PowerShell
    POST /api/scan/url        Analyze URL
    POST /api/scan/eml        Scan Email (.eml file)
    POST /api/scan/headers    Analyze pasted raw headers  ← NEW
    POST /api/whois           WHOIS + domain age check    ← NEW
    POST /api/vt/hash         Full VirusTotal hash lookup ← NEW
    POST /api/extract/iocs    Extract IOCs from text
    GET  /api/history         All scan history
    GET  /api/history/<id>    Single scan detail
    GET  /api/stats           Dashboard statistics
    GET  /api/search/ioc?q=   Search IOC database
    """)
    app.run(debug=True, host='0.0.0.0', port=5000)
