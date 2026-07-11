import requests

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
]

def scan_xss(url, params):
    findings = []
    for param in params:
        for payload in XSS_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            try:
                resp = requests.get(url, params=test_params, timeout=5)
                if payload in resp.text:
                    findings.append({
                        "type": "Reflected XSS",
                        "param": param,
                        "payload": payload,
                        "severity": "High"
                    })
                    break
            except Exception:
                pass
    return findings