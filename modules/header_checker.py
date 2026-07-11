import requests

SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-XSS-Protection",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

def check_headers(url):
    findings = []
    try:
        resp = requests.get(url, timeout=5, verify=False)
        for header in SECURITY_HEADERS:
            if header not in resp.headers:
                findings.append({
                    "type": "Missing Header",
                    "detail": f"{header} not set",
                    "severity": "Medium"
                })
    except Exception as e:
        findings.append({"type": "Error", "detail": str(e), "severity": "Info"})
    return findings