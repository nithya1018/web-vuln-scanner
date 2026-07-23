from flask import Flask, render_template, request, jsonify, send_file
from urllib.parse import urlparse, parse_qs
from modules.header_checker import check_headers
from modules.sqli_scanner import scan_sqli
from modules.xss_scanner import scan_xss
from modules.port_scanner import scan_ports
from modules.pdf_report import generate_pdf
from modules.simplify import build_simple_report
from modules.crawler import crawl, get_testable_urls
from datetime import datetime
import json
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url', '')
    deep_scan = data.get('deep_scan', False)

    parsed = urlparse(url)
    host = parsed.hostname

    all_sqli = []
    all_xss = []
    pages_scanned = [url]

    if deep_scan:
        discovered = crawl(url, max_pages=15)
        testable_urls = get_testable_urls(discovered)
        if url not in testable_urls:
            testable_urls.append(url)
        pages_scanned = discovered if discovered else [url]
    else:
        testable_urls = [url]

    for test_url in testable_urls:
        test_params = parse_qs(urlparse(test_url).query)
        test_params = {k: v[0] for k, v in test_params.items()}
        if test_params:
            all_sqli.extend(scan_sqli(test_url, test_params))
            all_xss.extend(scan_xss(test_url, test_params))

    results = {
        'headers': check_headers(url),
        'sqli':    all_sqli,
        'xss':     all_xss,
        'ports':   scan_ports(host),
        'pages_scanned': len(pages_scanned)
    }

    simple_report = build_simple_report(results)

    os.makedirs("reports", exist_ok=True)

    with open("reports/latest.json", "w") as f:
        json.dump({'url': url, 'findings': results, 'simple': simple_report}, f)

    history_path = "reports/history.json"
    history = []
    if os.path.exists(history_path):
        with open(history_path) as f:
            history = json.load(f)

    history.insert(0, {
        'url': url,
        'score': simple_report['score'],
        'verdict': simple_report['verdict'],
        'date': datetime.now().strftime("%Y-%m-%d %H:%M"),
        'critical': sum(1 for f in results.get('sqli', []) if f['severity'] == 'Critical'),
        'high': sum(1 for f in results.get('xss', []) if f['severity'] == 'High'),
        'medium': sum(1 for f in results.get('headers', []) if f['severity'] == 'Medium'),
        'info': sum(1 for f in results.get('ports', []) if f['severity'] == 'Info'),
    })

    history = history[:20]
    with open(history_path, "w") as f:
        json.dump(history, f, indent=2)

    return jsonify({'technical': results, 'simple': simple_report})

@app.route('/download-pdf')
def download_pdf():
    with open("reports/latest.json") as f:
        data = json.load(f)
    path = generate_pdf(data['simple'], data['url'])
    return send_file(path, as_attachment=True, download_name="vulnerability_report.pdf")

@app.route('/history')
def history():
    history_path = "reports/history.json"
    scans = []
    if os.path.exists(history_path):
        with open(history_path) as f:
            scans = json.load(f)
    return render_template('history.html', scans=scans)

if __name__ == '__main__':
    app.run(debug=True)