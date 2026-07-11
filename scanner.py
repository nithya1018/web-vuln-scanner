import argparse
from urllib.parse import urlparse, parse_qs
from modules.header_checker import check_headers
from modules.sqli_scanner import scan_sqli
from modules.xss_scanner import scan_xss
from modules.port_scanner import scan_ports
from colorama import Fore, Style, init
from jinja2 import Environment, FileSystemLoader
import json
import os
from datetime import datetime

init(autoreset=True)

def print_findings(findings, module_name):
    print(f"\n{Fore.CYAN}[{module_name}]{Style.RESET_ALL}")
    if not findings:
        print(f"  {Fore.GREEN}No issues found{Style.RESET_ALL}")
        return
    for f in findings:
        color = Fore.RED if f['severity'] in ('Critical', 'High') else Fore.YELLOW
        detail = f.get('detail') or f.get('param') or f.get('service') or ''
        print(f"  {color}[{f['severity']}]{Style.RESET_ALL} {f['type']}: {detail}")

def save_json_report(all_findings, output_path="reports/report.json"):
    os.makedirs("reports", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(all_findings, f, indent=2)
    print(f"\n{Fore.GREEN}[+] JSON report saved to {output_path}{Style.RESET_ALL}")

def save_html_report(all_findings, url, output_path="reports/report.html"):
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report.html")
    html = template.render(
        url=url,
        findings=all_findings,
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"{Fore.GREEN}[+] HTML report saved to {output_path}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("url", help="Target URL e.g. http://testsite.com?id=1")
    args = parser.parse_args()

    url = args.url
    parsed = urlparse(url)
    host = parsed.hostname
    params = parse_qs(parsed.query)
    params = {k: v[0] for k, v in params.items()}

    print(f"\n{Fore.GREEN}[*] Starting scan on: {url}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Target host: {host}{Style.RESET_ALL}")

    all_findings = {}

    print(f"\n{Fore.CYAN}[*] Checking security headers...{Style.RESET_ALL}")
    headers = check_headers(url)
    all_findings['headers'] = headers
    print_findings(headers, "Security Headers")

    print(f"\n{Fore.CYAN}[*] Scanning for SQL Injection...{Style.RESET_ALL}")
    sqli = scan_sqli(url, params)
    all_findings['sqli'] = sqli
    print_findings(sqli, "SQL Injection")

    print(f"\n{Fore.CYAN}[*] Scanning for XSS...{Style.RESET_ALL}")
    xss = scan_xss(url, params)
    all_findings['xss'] = xss
    print_findings(xss, "XSS")

    print(f"\n{Fore.CYAN}[*] Scanning open ports...{Style.RESET_ALL}")
    ports = scan_ports(host)
    all_findings['ports'] = ports
    print_findings(ports, "Port Scan")

    save_json_report(all_findings)
    save_html_report(all_findings, url)

if __name__ == "__main__":
    main()