import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

def crawl(start_url, max_pages=15):
    """Crawls a site starting from start_url, returns list of discovered URLs"""
    visited = set()
    to_visit = [start_url]
    discovered = []
    base_domain = urlparse(start_url).netloc

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = requests.get(url, timeout=5, verify=False)
            discovered.append(url)
        except Exception:
            continue

        try:
            soup = BeautifulSoup(resp.text, 'html.parser')

            # Find all links
            for link in soup.find_all('a', href=True):
                full_url = urljoin(url, link['href'])
                parsed = urlparse(full_url)

                # Stay on same domain only
                if parsed.netloc != base_domain:
                    continue
                # Skip files, anchors, mailto
                if any(full_url.lower().endswith(ext) for ext in ['.pdf', '.jpg', '.png', '.css', '.js', '.zip']):
                    continue
                if full_url not in visited and full_url not in to_visit:
                    to_visit.append(full_url)

            # Find form actions (often where SQLi/XSS lives)
            for form in soup.find_all('form', action=True):
                form_url = urljoin(url, form['action'])
                if form_url not in visited and form_url not in to_visit:
                    to_visit.append(form_url)

        except Exception:
            continue

    return discovered

def get_testable_urls(discovered_urls):
    """Filter to only URLs that have query parameters (good for SQLi/XSS testing)"""
    testable = []
    for url in discovered_urls:
        params = parse_qs(urlparse(url).query)
        if params:
            testable.append(url)
    return testable