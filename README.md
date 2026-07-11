# 🛡️ VulnScanner — Web Vulnerability Scanner

A full-stack web vulnerability scanner built with Python and Flask. Scans websites for common security vulnerabilities and generates professional reports.

## Features

- 🔍 **Security Header Analysis** — Detects missing HTTP security headers
- 💉 **SQL Injection Detection** — Tests parameters for SQL injection vulnerabilities
- ⚡ **XSS Detection** — Identifies reflected Cross-Site Scripting vulnerabilities
- 🔌 **Port Scanner** — Discovers open ports and exposed services
- 🕷️ **Web Crawler** — Auto-discovers pages across an entire site
- 📊 **Security Score** — Rates the site out of 100
- 📝 **PDF Reports** — Generates professional downloadable reports
- 👤 **Simple & Technical Views** — Plain English for clients, technical details for developers
- 🔐 **Login System** — Protected access with session authentication
- 📜 **Scan History** — Dashboard of all past scans

## Tech Stack

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, JavaScript
- **Libraries:** Requests, BeautifulSoup4, ReportLab, Jinja2
- **Architecture:** Modular (each scanner is a separate module)

## Installation

```bash
# Clone the repo
git clone https://github.com/nithya1018/web-vuln-scanner.git
cd web-vuln-scanner

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Mac/Linux

# Install dependencies
pip install flask requests beautifulsoup4 colorama dnspython jinja2 termcolor urllib3 reportlab flask-login

# Create config.py
echo USERNAME = "admin" > config.py
echo PASSWORD = "yourpassword" >> config.py
echo SECRET_KEY = "your-secret-key" >> config.py

# Run the app
python app.py
```

Then open `http://127.0.0.1:5000` in your browser.

## Usage

1. Login with your credentials
2. Enter a target URL
3. Choose normal or deep scan
4. View results in Simple or Technical view
5. Download PDF report

## ⚠️ Legal Disclaimer

Only scan websites you own or have explicit written permission to test. Unauthorized scanning is illegal.

## Author

Built by [@nithya1018](https://github.com/nithya1018)