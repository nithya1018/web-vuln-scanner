# Maps technical findings to plain-English explanations for normal users

HEADER_EXPLANATIONS = {
    "X-Frame-Options": {
        "title": "Your site can be embedded inside fake pages",
        "explain": "Hackers can put your website inside an invisible frame on their own page and trick your visitors into clicking things without knowing it (called clickjacking).",
        "fix": "Ask your developer to add the X-Frame-Options header to block this.",
        "risk": "Medium"
    },
    "X-XSS-Protection": {
        "title": "Old browser protection against script attacks is missing",
        "explain": "Some older browsers had a built-in shield against malicious scripts. Your site doesn't have it turned on.",
        "fix": "Add the X-XSS-Protection header as an extra safety net.",
        "risk": "Low"
    },
    "Content-Security-Policy": {
        "title": "No restrictions on what scripts can run on your site",
        "explain": "If a hacker manages to inject malicious code into your site, there's nothing stopping it from running and stealing visitor data.",
        "fix": "Ask your developer to set up a Content-Security-Policy to control what scripts are allowed to run.",
        "risk": "Medium"
    },
    "Strict-Transport-Security": {
        "title": "Visitors can be downgraded to an unsafe connection",
        "explain": "Your site doesn't force browsers to always use a secure (HTTPS) connection, so attackers on public WiFi could intercept data.",
        "fix": "Add the Strict-Transport-Security header to force secure connections.",
        "risk": "Medium"
    },
    "X-Content-Type-Options": {
        "title": "Browsers may misinterpret your files",
        "explain": "Without this setting, browsers might run a file as something it's not supposed to be (like running an image as code).",
        "fix": "Add the X-Content-Type-Options header.",
        "risk": "Low"
    },
    "Referrer-Policy": {
        "title": "Visitor browsing data may leak to other sites",
        "explain": "When someone clicks a link from your site, the destination site can see exactly which page they came from, possibly exposing private info.",
        "fix": "Set a Referrer-Policy header to control what gets shared.",
        "risk": "Low"
    },
    "Permissions-Policy": {
        "title": "No control over browser features like camera or location",
        "explain": "Without this, embedded content on your site could request access to a visitor's camera, microphone, or location.",
        "fix": "Add a Permissions-Policy header to restrict these features.",
        "risk": "Low"
    },
}

def simplify_headers(findings):
    simplified = []
    for f in findings:
        header_name = f['detail'].split(' ')[0]
        info = HEADER_EXPLANATIONS.get(header_name)
        if info:
            simplified.append({
                "title": info["title"],
                "explain": info["explain"],
                "fix": info["fix"],
                "risk": info["risk"]
            })
    return simplified

def simplify_sqli(findings):
    simplified = []
    for f in findings:
        simplified.append({
            "title": f"Hackers may be able to steal your database through '{f['param']}'",
            "explain": "Your website doesn't properly check what users type into a form or link. A hacker could type special commands instead of normal text and trick your database into revealing private information like customer data, passwords, or orders.",
            "fix": "This is serious — ask your developer to fix this immediately by validating all user input before using it in database queries.",
            "risk": "Critical"
        })
    return simplified

def simplify_xss(findings):
    simplified = []
    for f in findings:
        simplified.append({
            "title": f"Hackers can inject fake content through '{f['param']}'",
            "explain": "Your site shows back whatever a user types without checking it first. A hacker could send a link that, when clicked, runs malicious code in your visitor's browser — stealing their login session or showing fake popups.",
            "fix": "Ask your developer to sanitize user input before displaying it on the page.",
            "risk": "High"
        })
    return simplified

def simplify_ports(findings):
    simplified = []
    risky_ports = {21: "Medium", 23: "High", 3389: "High", 3306: "Medium", 5432: "Medium"}
    for f in findings:
        port = f['port']
        risk = risky_ports.get(port, "Low")
        simplified.append({
            "title": f"Open door found: {f['service']} (port {port})",
            "explain": f"Your server has the {f['service']} service exposed to the internet. If it's outdated or weakly secured, hackers can use this as an entry point into your server.",
            "fix": "Make sure this service is necessary, updated, and protected with a strong password or firewall rule. Close it if not needed.",
            "risk": risk
        })
    return simplified

def calculate_score(simplified_findings):
    """Returns a score out of 100 based on findings severity"""
    score = 100
    weights = {"Critical": 20, "High": 12, "Medium": 6, "Low": 2}
    for f in simplified_findings:
        score -= weights.get(f['risk'], 2)
    return max(score, 0)

def build_simple_report(raw_findings):
    headers_s = simplify_headers(raw_findings.get('headers', []))
    sqli_s    = simplify_sqli(raw_findings.get('sqli', []))
    xss_s     = simplify_xss(raw_findings.get('xss', []))
    ports_s   = simplify_ports(raw_findings.get('ports', []))

    all_findings = headers_s + sqli_s + xss_s + ports_s
    score = calculate_score(all_findings)

    if score >= 85:
        verdict = "Good — minor issues only"
    elif score >= 60:
        verdict = "Needs attention"
    else:
        verdict = "At risk — fix urgently"

    return {
        "score": score,
        "verdict": verdict,
        "findings": all_findings
    }