import httpx
import random
import time

from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse
import tldextract

# Set the HTML size limit
MAX_SIZE_KB = 220

# List of common User-Agent strings to rotate
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
]

# Async Function: Fetch HTML from URL
async def fetch_html(url, max_size_kb=MAX_SIZE_KB):
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    timeout = httpx.Timeout(connect=3.0, read=3.0, write=2.0, pool=2.0)
    limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)

    try:
        async with httpx.AsyncClient(timeout=timeout, limits=limits, follow_redirects=True, max_redirects=3) as client:
            async with client.stream("GET", url, headers=headers) as response:
                
                # Log redirect info
                if response.history:
                    print(f"Redirected {len(response.history)} times. Final URL: {response.url}")

                response.raise_for_status()

                # Early exit if Content-Length exceeds limit
                if response.headers.get("content-length"):
                    size = int(response.headers["content-length"])
                    if size > max_size_kb * 1024:
                        print(f"Content-Length too large: {size} bytes. Skipping.")
                        return None

                # Read stream up to size limit
                content = b""
                start = time.time()
                async for chunk in response.aiter_bytes(chunk_size=8192):
                    content += chunk
                    if len(content) > max_size_kb * 1024:  # Stop if size exceeds limit
                        break
                    if time.time() - start > 3:  # Stop if reading takes too long
                        print("Fetch timed out during streaming.")
                        break

                return content.decode(errors="ignore")
    except httpx.TooManyRedirects:
        print(f"Too many redirects for {url}")
        return None
    except httpx.RequestError as e:
        print(f"Error fetching URL: {e}")
        return None

# Precompiled regex patterns for performance
BASE64_PATTERN = re.compile(r'base64,[A-Za-z0-9+/=]+')
IP_ADDRESS_PATTERN = re.compile(r'http[s]?://\d{1,3}(?:\.\d{1,3}){3}')
URL_ENCODING_PATTERN = re.compile(r'%[0-9a-fA-F]{2}')

# Function: Extract textual and heuristic features
def extract_features(url, html, max_size_kb=MAX_SIZE_KB, max_tokens=512, skip_dom_if_large=True):
    def safe_urlparse(url):
        try:
            return urlparse(url)
        except ValueError:
            return None
            
    parsed = safe_urlparse(url)
    extracted = tldextract.extract(url)
    domain = parsed.netloc if parsed else ''
    tld = extracted.suffix

    # URL-based features
    heuristic_features = {
        'url_length': len(url),
        'num_dots': url.count('.'),
        'has_at_symbol': '@' in url,
        'uses_https': parsed.scheme == 'https' if parsed else False,
        'suspicious_words': int(any(word in url.lower() for word in ['login', 'verify', 'secure', 'update'])),
        'has_ip_address': bool(IP_ADDRESS_PATTERN.search(url)),
        'num_subdomains': max(0, len(domain.split('.')) - 2) if domain else 0,
        'is_suspicious_tld': tld in ['tk', 'ml', 'ga', 'cf', 'gq'],
        'has_hyphen': '-' in domain,
        'url_has_encoding': '%' in url or bool(URL_ENCODING_PATTERN.search(url)),
        'url_has_long_query': len(parsed.query) > 100 if parsed else False,
        'url_ends_with_exe': url.lower().endswith('.exe'),
    }

    # Fallback: If no HTML, return URL-only features
    if html is None or not html.strip():
        heuristic_features.update({
            'num_forms': 0, 'num_inputs': 0, 'num_links': 0,
            'num_password_inputs': 0, 'num_hidden_inputs': 0,
            'num_onclick_events': 0, 'num_hidden_elements': 0,
            'has_iframe': False, 'has_zero_sized_iframe': False,
            'suspicious_form_action': False, 'has_script_eval': False,
            'has_network_js': False, 'has_base64_in_js': False,
            'num_inline_scripts': 0, 'external_js_count': 0,
            'external_iframe_count': 0, 'num_external_domains': 0
        })
        return "", heuristic_features

    # Skip DOM parsing for huge pages (optional)
    if skip_dom_if_large and len(html) > 1024 * max_size_kb:
        heuristic_features.update({
            'num_forms': 0, 'num_inputs': 0, 'num_links': 0,
            'num_password_inputs': 0, 'num_hidden_inputs': 0,
            'num_onclick_events': 0, 'num_hidden_elements': 0,
            'has_iframe': False, 'has_zero_sized_iframe': False,
            'suspicious_form_action': False, 'has_script_eval': False,
            'has_network_js': False, 'has_base64_in_js': False,
            'num_inline_scripts': 0, 'external_js_count': 0,
            'external_iframe_count': 0, 'num_external_domains': 0
        })
        return "", heuristic_features

    # Parse HTML once
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    # Extract and clean text
    text = soup.get_text(separator=" ", strip=True)
    text = re.sub(r"\s+", " ", text).strip().lower()
    text = re.sub(r'[^\w\s.,!?-]', '', text)

    MAX_CHARS = 20000  # ~20 KB of text
    tokens = text.split()
    if len(tokens) > max_tokens:
        tokens = tokens[:max_tokens]
    visible_text = " ".join(tokens)[:MAX_CHARS]

    # DOM-based features
    forms = soup.find_all('form')
    inputs = soup.find_all('input')
    links = soup.find_all('a')
    iframes = soup.find_all('iframe')
    script_tags = soup.find_all('script')

    external_domains = {
        safe_urlparse(tag.get('src') or tag.get('href')).netloc
        for tag in soup.find_all(['script', 'link', 'img', 'iframe'])
        if (tag.get('src') or tag.get('href')) and safe_urlparse(tag.get('src') or tag.get('href')).netloc != domain
    }

    inline_scripts = [s for s in script_tags if not s.get('src')]
    js_keywords = ['fetch(', 'XMLHttpRequest', 'navigator.sendBeacon', 'new WebSocket']
    has_network_js = any(keyword in html for keyword in js_keywords)
    base64_matches = BASE64_PATTERN.findall(html)

    heuristic_features.update({
        'num_forms': len(forms),
        'num_inputs': len(inputs),
        'num_links': len(links),
        'num_password_inputs': sum(1 for inp in inputs if inp.get('type') == 'password'),
        'num_hidden_inputs': sum(1 for inp in inputs if inp.get('type') == 'hidden'),
        'num_onclick_events': len(soup.find_all(onclick=True)),
        'num_hidden_elements': len(soup.select('[style*="display:none"], [style*="visibility:hidden"]')),
        'has_iframe': bool(iframes),
        'has_zero_sized_iframe': any(
            iframe.get('width') in ['0', '1'] or iframe.get('height') in ['0', '1']
            for iframe in iframes
        ),
        'suspicious_form_action': any(
            form.get('action') and safe_urlparse(form.get('action')) and safe_urlparse(form.get('action')).netloc not in ['', domain]
            for form in forms
        ),
        'has_script_eval': 'eval(' in html,
        'has_network_js': has_network_js,
        'has_base64_in_js': len(base64_matches) > 0,
        'num_inline_scripts': len(inline_scripts),
        'external_js_count': sum(
            1 for tag in script_tags if tag.get('src') and safe_urlparse(tag.get('src')) and safe_urlparse(tag.get('src')).netloc != domain
        ),
        'external_iframe_count': sum(
            1 for iframe in iframes if iframe.get('src') and safe_urlparse(iframe.get('src')) and safe_urlparse(iframe.get('src')).netloc != domain
        ),
        'num_external_domains': len(external_domains),
    })

    return visible_text, heuristic_features
