# 🔍 SecretFinder — Advanced Edition

![SecretFinder Banner](images/banner.png)

> **Rewritten & Enhanced by [Xnuvers007](https://github.com/Xnuvers007/SecretFinder)**  
> [English Version (README_EN.md)](README_EN.md)  
> Original by [m4ll0k](https://github.com/m4ll0k/SecretFinder) · Based on [LinkFinder](https://github.com/GerbenJavado/LinkFinder)

SecretFinder adalah **tool Python profesional** untuk menemukan data sensitif — API keys, access token, JWT, credentials, private key, dan lainnya — yang tersembunyi di dalam file JavaScript.

---

## ✨ Fitur Advanced Edition

| Fitur | Original | Advanced Edition |
|---|---|---|
| Regex patterns | ~20 | **118+** |
| Severity scoring | ✗ | ✅ CRITICAL / HIGH / MEDIUM / LOW / INFO |
| Output format | HTML saja | **HTML dark · JSON · CSV · CLI berwarna** |
| Concurrent scan | ✗ | ✅ ThreadPoolExecutor (configurable) |
| Retry logic | ✗ | ✅ Exponential back-off |
| Output Folder | ✗ | ✅ Auto-creates `output/` folder |
| Auto-increment | ✗ | ✅ `results.html` → `results2.html` (no overwrite) |
| Input bare domain | ✗ | ✅ `example.com` → auto `https://example.com` |
| Input alias | `-i` | ✅ `-i` / `-u` / `--input` / `--url` |
| Scheme pilihan | ✗ | ✅ `--http` / `--https` (default: https) |
| Arsitektur | 1 file | ✅ Modular (`core/` package) |
| HTML report | Basic | ✅ **Premium dark-mode dashboard** |
| Burp Extension | Basic | ✅ **Updated with 118+ Patterns** |

---

## 📦 Instalasi

```bash
git clone https://github.com/Xnuvers007/SecretFinder.git
cd SecretFinder

# Buat virtual environment (opsional tapi disarankan)
python -m venv venv
venv\Scripts\activate       # Windows
source venv/bin/activate    # Linux/Mac

pip install -r requirements.txt
python SecretFinder.py --help
```

---

## 🚀 Panduan Penggunaan — Dari A sampai Z

### 1. Input paling simpel — cukup ketik domain

```bash
python SecretFinder.py -i example.com
python SecretFinder.py -i www.example.com
python SecretFinder.py -i sub.domain.example.com
python SecretFinder.py -i www.api.v2.staging.example.co.uk   # multi-level subdomain
```
> Semua otomatis jadi `https://...`. Tidak perlu ketik `http://` atau `https://`.

---

### 1b. Input IPv4 (dengan/tanpa port)

```bash
python SecretFinder.py -i 192.168.1.1 -o cli
python SecretFinder.py -i 192.168.1.1:8080 -o cli
python SecretFinder.py -i 10.0.0.1:9200/api --http -o cli    # paksa http
python SecretFinder.py -i 172.16.0.1:3000/swagger -e
```

---

### 1c. Input IPv6

```bash
python SecretFinder.py -i "[::1]:8080" -o cli
python SecretFinder.py -i "[fe80::1]:443" --http -o cli
```

---

### 1d. Domain + port + path

```bash
python SecretFinder.py -i example.com:8443 -e
python SecretFinder.py -i api.example.com:3000/v2 -o cli
python SecretFinder.py -i internal.corp.local:8080/graphql -o cli --http
```


### 2. Scan seluruh JS di sebuah domain (mode extract)

```bash
python SecretFinder.py -i example.com -e
```
> `-e` / `--extract` → ambil semua `<script src="...">` dari halaman, lalu scan semua JS-nya.

---

### 3. Subdomain

```bash
python SecretFinder.py -i api.example.com -e
python SecretFinder.py -i cdn.example.com/static/app.js -o cli
```

---

### 4. Paksa HTTP (bukan HTTPS)

```bash
python SecretFinder.py -i example.com -e --http
```
> Gunakan `--https` (default) atau `--http` untuk memilih scheme pada bare domain.

---

### 5. URL lengkap (tetap bisa)

```bash
python SecretFinder.py -i https://example.com/assets/app.js
python SecretFinder.py -i http://192.168.1.1/js/main.js
```

---

### 6. Output ke CLI (cepat, tanpa HTML)

```bash
python SecretFinder.py -i example.com -e -o cli
```
> Output langsung ke terminal dengan warna. Tidak membuka browser.

---

### 7. Output ke HTML (default)

```bash
python SecretFinder.py -i example.com -e
```
> **Fitur Baru:** Secara default, hasil akan disimpan di folder `output/results.html`. 
> Jika file sudah ada, tool akan otomatis membuat file baru: `results2.html`, `results3.html`, dst. (Anti-Overwrite).

```bash
# Simpan ke file custom (folder akan otomatis dibuat jika belum ada)
python SecretFinder.py -i example.com -e -o my_results/scan.html
```

---

### 8. Output ke JSON

```bash
python SecretFinder.py -i example.com -e --format json -o hasil.json
# atau auto-detect dari ekstensi:
python SecretFinder.py -i example.com -e -o hasil.json
```

---

### 9. Output ke CSV

```bash
python SecretFinder.py -i example.com -e -o hasil.csv
```

---

### 10. Filter berdasarkan severity

```bash
# Hanya tampilkan CRITICAL dan HIGH
python SecretFinder.py -i example.com -e -o cli --severity CRITICAL HIGH

# Hanya CRITICAL saja
python SecretFinder.py -i example.com -e -o cli --severity CRITICAL
```

---

### 11. Alias input — semua cara ini sama

```bash
python SecretFinder.py -i example.com -e
python SecretFinder.py -u example.com -e
python SecretFinder.py --input example.com -e
python SecretFinder.py --url example.com -e
```

---

### 12. Scan file JS lokal

```bash
python SecretFinder.py -i /path/to/app.js -o cli
python SecretFinder.py -i "C:\Users\user\Downloads\app.js" -o cli
```

---

### 13. Scan banyak file sekaligus (glob pattern)

```bash
# Semua .js di folder
python SecretFinder.py -i "/path/to/js/*.js" -o hasil.json

# Dengan filter CRITICAL saja
python SecretFinder.py -i "/path/to/js/*.js" --severity CRITICAL -o cli
```

---

### 14. Ignore JS tertentu (library eksternal)

```bash
# Skip jQuery, Bootstrap, dan Google API
python SecretFinder.py -i example.com -e -g "jquery;bootstrap;apis.google.com"
```

---

### 15. Hanya proses JS tertentu

```bash
# Hanya scan JS dari CDN sendiri
python SecretFinder.py -i example.com -e -n "cdn.example.com;assets.example.com"
```

---

### 16. Dengan cookies (autentikasi)

```bash
python SecretFinder.py -i example.com -e -o cli \
  -c "session=abc123; token=xyz789"
```

---

### 17. Dengan custom headers

```bash
python SecretFinder.py -i example.com -e -o cli \
  -H "Authorization:Bearer mytoken\nX-Api-Key:secret123"
```

---

### 18. Dengan proxy (Burp Suite / mitmproxy)

```bash
python SecretFinder.py -i example.com -e -o cli \
  -p http://127.0.0.1:8080
```

---

### 19. Semua opsi HTTP sekaligus

```bash
python SecretFinder.py -i example.com -e -o hasil.html \
  -c "session=abc" \
  -H "X-Auth:mytoken" \
  -p http://127.0.0.1:8080 \
  --timeout 30 \
  --retries 5 \
  --delay 1.5 \
  --user-agent "Mozilla/5.0 (custom)"
```

---

### 20. Custom regex sendiri

```bash
# Tambahkan regex kustom
python SecretFinder.py -i example.com/app.js -o cli \
  -r "myapp_[a-zA-Z0-9]{32}" --regex-name myapp_token
```

---

### 21. Burp Suite XML export

```bash
# Export dari Burp: Project → Save items → XML
python SecretFinder.py -i burp_export.xml -b -o hasil.html
```

---

### 22. Mode cepat (skip jsbeautifier)

```bash
# Lebih cepat, context sedikit berkurang
python SecretFinder.py -i example.com -e -o cli --fast
```

---

### 23. Multi-thread (scan banyak JS paralel)

```bash
# Default: 10 thread. Naikkan untuk target besar
python SecretFinder.py -i example.com -e -o cli -t 20
```

---

### 24. Verbose / debug mode

```bash
python SecretFinder.py -i example.com -e -o cli -v
```

---

### 25. Tanpa banner / tanpa warna

```bash
python SecretFinder.py -i example.com -e -o cli --no-banner
python SecretFinder.py -i example.com -e -o cli --no-color
```

---

### 26. Kombinasi lengkap (contoh real-world)

```bash
# Scan domain, extract semua JS, filter CRITICAL+HIGH,
# skip library umum, output JSON, dengan proxy Burp
python SecretFinder.py \
  -i target.com \
  -e \
  --severity CRITICAL HIGH \
  -g "jquery;bootstrap;cloudflare;google" \
  -c "PHPSESSID=abc123" \
  -H "X-Forwarded-For:127.0.0.1" \
  -p http://127.0.0.1:8080 \
  -o hasil.json \
  -t 15 \
  -v
```

---

### 27. Docker

```bash
docker build -t secretfinder .

# Scan dan lihat di terminal
docker run --rm secretfinder -i example.com -e -o cli

# Simpan HTML report ke folder lokal
docker run --rm -v "%cd%:/out" secretfinder -i example.com -e -o /out/report.html
```

---

## ⚙️ Semua Opsi Lengkap

```
Input / Output:
  -i / -u / --input / --url   Target: domain, URL, file lokal, glob, atau Burp XML
  -o, --output                Output path atau 'cli' (default: output.html)
  --format                    html | json | csv | cli

Scheme:
  --https                     Gunakan HTTPS untuk bare domain (default)
  --http                      Gunakan HTTP untuk bare domain

Extraction:
  -e, --extract               Ekstrak semua <script src> dari halaman HTML
  -b, --burp                  Input adalah file XML export Burp Suite
  -g, --ignore                Skip JS URL yang mengandung string ini (pisah pakai ;)
  -n, --only                  Hanya proses JS URL yang mengandung string ini

HTTP:
  -c, --cookie                String cookie
  -H, --headers               Custom headers ("Name:Value\nName2:Value2")
  -p, --proxy                 Proxy HTTP (http://host:port)
  --timeout                   Timeout request dalam detik (default: 15)
  --retries                   Jumlah retry jika gagal (default: 3)
  --delay                     Jeda antar request dalam detik (default: 0)
  --user-agent                Custom User-Agent string

Scanning:
  -r, --regex                 Tambahkan regex kustom
  --regex-name                Nama untuk regex kustom
  --severity                  Filter severity: CRITICAL HIGH MEDIUM LOW INFO
  --allow-duplicates          Jangan deduplikasi hasil
  --fast                      Skip jsbeautifier (lebih cepat)
  -t, --threads               Jumlah thread paralel (default: 10)

Misc:
  --no-color                  Nonaktifkan warna ANSI
  --no-banner                 Sembunyikan ASCII banner
  -v, --verbose               Logging debug
  --version                   Tampilkan versi
```

---

## 🎯 Severity Levels

| Level | Warna | Contoh |
|---|---|---|
| 🔴 **CRITICAL** | Merah | AWS keys, Stripe live keys, private keys, DB connection strings, Discord/Telegram bot tokens |
| 🟠 **HIGH** | Orange | Bearer tokens, JWT, Slack tokens, SendGrid keys, Heroku API keys |
| 🟡 **MEDIUM** | Kuning | Google reCAPTCHA keys, Mapbox tokens, Amazon S3 URLs |
| 🔵 **LOW** | Biru | Internal IP, localhost endpoints, email addresses |
| ⚫ **INFO** | Abu | IPv4 addresses |

---

## 🗂 Struktur Proyek

```
SecretFinder/
├── SecretFinder.py          # CLI entry point
├── core/
│   ├── __init__.py
│   ├── patterns.py          # 60+ regex + severity scoring
│   ├── scanner.py           # Scanning engine
│   ├── fetcher.py           # HTTP fetcher (retry, proxy)
│   ├── input_parser.py      # Input resolver + JS extractor
│   └── output.py            # HTML / JSON / CSV / CLI renderers
├── BurpSuite-SecretFinder/
├── requirements.txt
├── Dockerfile
└── README.md
```

---

## ⚠️ Disclaimer

Tool ini untuk **security research dan penetration testing yang sah** saja.  
Menggunakannya pada sistem tanpa izin adalah **ilegal**.  
Penulis tidak bertanggung jawab atas penyalahgunaan.

---

<div align="center">

Made with ❤️ by [Xnuvers007](https://github.com/Xnuvers007)  
Original tool by [m4ll0k](https://github.com/m4ll0k)

</div>
