import requests

PAYLOADS = ["'", "''", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1"]
ERROR_PATTERNS = ["sql syntax", "mysql_fetch", "unclosed quotation", "syntax error"]

def scan_sqli(url, params):
    findings = []
    for param in params:
        for payload in PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            try:
                resp = requests.get(url, params=test_params, timeout=5)
                for pattern in ERROR_PATTERNS:
                    if pattern.lower() in resp.text.lower():
                        findings.append({
                            "type": "SQL Injection",
                            "param": param,
                            "payload": payload,
                            "severity": "Critical"
                        })
                        break
            except Exception:
                pass
    return findings