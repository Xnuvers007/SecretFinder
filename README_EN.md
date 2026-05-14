# 🔍 SecretFinder — Advanced Edition

![SecretFinder Banner](images/banner.png)

> **Rewritten & Enhanced by [Xnuvers007](https://github.com/Xnuvers007/SecretFinder)**  
> [Indonesian Version (README.md)](README.md)  
> Original by [m4ll0k](https://github.com/m4ll0k/SecretFinder) · Based on [LinkFinder](https://github.com/GerbenJavado/LinkFinder)

---

**SecretFinder Advanced Edition** is a powerful tool designed for security researchers and bug hunters to discover sensitive information (API keys, tokens, credentials) in JavaScript files. This version has been completely rewritten into a modular architecture with significantly expanded detection capabilities.

## 🚀 Key Features

| Feature | Original | Advanced Edition |
|---|---|---|
| Regex patterns | ~20 | **118+** |
| Severity scoring | ✗ | ✅ CRITICAL / HIGH / MEDIUM / LOW / INFO |
| Output formats | HTML only | **HTML Dark · JSON · CSV · CLI (Colored)** |
| Concurrent scanning | ✗ | ✅ ThreadPoolExecutor (configurable) |
| Retry logic | ✗ | ✅ Exponential back-off |
| Output Folder | ✗ | ✅ Auto-creates `output/` folder |
| Auto-increment | ✗ | ✅ `results.html` → `results2.html` (prevent overwrite) |
| Bare domain input | ✗ | ✅ `example.com` → auto `https://example.com` |
| Input aliases | `-i` | ✅ `-i` / `-u` / `--input` / `--url` |
| Scheme selection | ✗ | ✅ `--http` / `--https` (default: https) |
| Architecture | 1 file | ✅ Modular (`core/` package) |
| HTML report | Basic | ✅ **Premium dark-mode dashboard** |
| Burp Extension | Basic | ✅ **Updated with 118+ Patterns** |

---

## 🛠️ Installation

### 1. Requirements
- Python 3.8+
- pip

### 2. Setup
```bash
git clone https://github.com/Xnuvers007/SecretFinder.git
cd SecretFinder
pip install -r requirements.txt
```

---

## 📖 Usage Examples (A to Z)

### 1. Simple Domain Scan (Auto-HTTPS)
```bash
python SecretFinder.py -u example.com -e
```
> All inputs like `example.com` or `api.target.io` are automatically resolved to `https://...`.

### 2. Scan Specific JS URL
```bash
python SecretFinder.py -u https://example.com/assets/main.js -o cli
```

### 3. Deep Extraction Mode
Scan a page, find all `<script src>` links, and scan them concurrently:
```bash
python SecretFinder.py -u https://target.com/app -e -o output/deep_scan.html
```

### 4. Input Formats (Smart Normalization)
SecretFinder is smart. You can use IPs, subdomains, or custom ports:
```bash
python SecretFinder.py -i 192.168.1.1 -o cli
python SecretFinder.py -i 10.0.0.1:8080 --http -o cli
python SecretFinder.py -i sub.dev.api.target.com -e
```

### 5. Filter by Severity
Only see what matters:
```bash
python SecretFinder.py -u target.com -e --severity CRITICAL HIGH
```

### 6. Local File & Glob Scan
```bash
# Scan a single file
python SecretFinder.py -i local_script.js -o cli

# Scan a folder using glob
python SecretFinder.py -i "js_files/*.js" -o results.json
```

### 7. Output Management
By default, reports are saved in the `output/` folder.
```bash
python SecretFinder.py -i example.com -e
```
> **Feature:** If `results.html` exists, it will auto-increment to `results2.html`, `results3.html`, etc.

---

## 🔌 Burp Suite Integration

The Burp Suite extension has been updated with the same **118+ patterns**.
1. Open Burp Suite.
2. Go to `Extender` -> `Extensions`.
3. Click `Add`.
4. Select Extension type: `Python`.
5. Select `BurpSuite-SecretFinder/SecretFinder.py`.

---

## 🛡️ Detection Capabilities (118+ Patterns)
- **AI/LLM**: OpenAI, Anthropic, HuggingFace, etc.
- **Cloud**: AWS (S3, MWS, Keys), Azure, GCP, Cloudflare.
- **CI/CD**: Jenkins, CircleCI, GitHub Actions, GitLab.
- **Databases**: MongoDB SRV, Redis, PostgreSQL, MySQL.
- **Payments**: Stripe, PayPal, Razorpay, Braintree.
- **Crypto**: Ethereum/Bitcoin Private Keys, Mnemonic phrases.
- **Docs**: Finding sensitive documents (`.xlsx`, `.pdf`, `.docx`, etc.) referenced in code.

---

## ⚠️ Warning: False Positives
Security scanning based on regex may produce **false positives** (e.g., example strings, documentation links, or generic UUIDs).
- Look for the ⚠️ warning banner in your HTML reports.
- Manual verification is **always recommended** before reporting a finding.

---

## 📁 Project Structure
```text
SecretFinder/
├── SecretFinder.py       # Main Entry Point
├── core/                 # Core Engine
│   ├── patterns.py       # 118+ Security Patterns
│   ├── scanner.py        # Scan Logic
│   ├── fetcher.py        # Request & Extract Logic
│   ├── input_parser.py   # Smart Input Normalizer
│   └── output.py         # Formatters (HTML/JSON/CSV/CLI)
├── images/               # Visual Assets
├── output/               # Default results directory
├── BurpSuite-SecretFinder/
├── requirements.txt
├── Dockerfile
└── README.md
```

---

## 📜 Disclaimer
This tool is for **legal security research and penetration testing** only. Using it on systems without permission is **illegal**. The author is not responsible for any misuse.

---

**Developed by [Xnuvers007](https://github.com/Xnuvers007)**
