import os
import sys
import time
import requests
import traceback
import pandas as pd
from typing import List, Dict
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re

# ----- CONFIGURATION ----- #

JSON_URL = "http://data.phishtank.com/data/online-valid.json"
max_retries = 5 
retry_delay = 600

# ----- HELPER FUNCTIONS ----- #

def fetch_html(url: str) -> str:
    """
    Fetch HTML content using requests
    """
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/114.0.0.0 Safari/537.36"
            )
        }
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

def extract_text(html):
    """
    Extract textual features from HTML content
    """
    if html is None:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    for script in soup(["script", "style"]):
        script.decompose()
    return soup.get_text(separator=" ", strip=True)

def extract_heuristic(row):
    """
    Extract heuristic features from URL and HTML content
    """
    url = row['url']
    html = row['html_content']
    parsed = urlparse(url)
    domain = parsed.netloc
    features = {
        'url_length': len(url),
        'num_dots': url.count('.'),
        'has_at_symbol': '@' in url,
        'uses_https': parsed.scheme == 'https',
        'suspicious_words': int(any(word in url.lower() for word in ['login', 'verify', 'secure', 'update'])),
        'has_ip_address': bool(re.search(r'http[s]?://\d{1,3}(?:\.\d{1,3}){3}', url)),
        'num_subdomains': len(parsed.netloc.split('.')) - 2,
        'is_suspicious_tld': parsed.netloc.split('.')[-1] in ['tk', 'ml', 'ga', 'cf', 'gq'],
        'has_hyphen': '-' in parsed.netloc,
        'url_has_encoding': '%' in url or re.search(r'%[0-9a-fA-F]{2}', url) is not None,
        'url_has_long_query': len(parsed.query) > 100,
        'url_ends_with_exe': url.lower().endswith('.exe'),
    }
    if html:
        soup = BeautifulSoup(html, 'html.parser')
        external_domains = set()
        for tag in soup.find_all(['script', 'link', 'img', 'iframe']):
            src = tag.get('src') or tag.get('href')
            if src:
                parsed_src = urlparse(src)
                if parsed_src.netloc and parsed_src.netloc != domain:
                    external_domains.add(parsed_src.netloc)
        js_keywords = ['fetch(', 'XMLHttpRequest', 'navigator.sendBeacon', 'new WebSocket']
        has_network_js = any(keyword in html for keyword in js_keywords)
        script_tags = soup.find_all('script')
        inline_scripts = [s for s in script_tags if not s.get('src')]
        base64_matches = re.findall(r'base64,[A-Za-z0-9+/=]+', html)
        features.update({
            'num_forms': len(soup.find_all('form')),
            'num_inputs': len(soup.find_all('input')),
            'num_links': len(soup.find_all('a')),
            'num_password_inputs': len(soup.find_all('input', {'type': 'password'})),
            'num_hidden_inputs': len(soup.find_all('input', {'type': 'hidden'})),
            'num_onclick_events': len(soup.find_all(onclick=True)),
            'num_hidden_elements': len(soup.select('[style*="display:none"], [style*="visibility:hidden"]')),
            'has_iframe': bool(soup.find('iframe')),
            'has_zero_sized_iframe': any(
                iframe.get('width') in ['0', '1'] or iframe.get('height') in ['0', '1']
                for iframe in soup.find_all('iframe')
            ),
            'suspicious_form_action': any(
                form.get('action') and urlparse(form.get('action')).netloc not in ['', domain]
                for form in soup.find_all('form')
            ),
        })
        features.update({
            'has_script_eval': 'eval(' in html,
            'has_network_js': has_network_js,
            'has_base64_in_js': len(base64_matches) > 0,
            'num_inline_scripts': len(inline_scripts),
            'external_js_count': len([
                tag for tag in script_tags
                if tag.get('src') and urlparse(tag.get('src')).netloc != domain
            ]),
            'external_iframe_count': len([
                tag for tag in soup.find_all('iframe')
                if tag.get('src') and urlparse(tag.get('src')).netloc != domain
            ]),
            'num_external_domains': len(external_domains),
        })
    else:
        features.update({key: 0 if isinstance(val, int) else False for key, val in features.items()})
    return pd.Series(features)

# ----- MAIN FUNCTION ----- #

def main():
    # Fetch JSON data
    for attempt in range(max_retries):
        try:
            print(f"Attempt {attempt + 1} of {max_retries} to fetch data...", flush=True)
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/114.0.0.0 Safari/537.36"
                )
            }
            response = requests.get(JSON_URL, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            print("Successfully fetched JSON.", flush=True)
            break
        except Exception as e:
            print(f"Error fetching data (attempt {attempt + 1}): {e}", flush=True)
            traceback.print_exc()
            if attempt < max_retries - 1:
                print(f"Waiting {retry_delay} seconds before retry...", flush=True)
                time.sleep(retry_delay)
            else:
                print("Max retries reached. Exiting.", flush=True)
                sys.exit(1)

    # Convert to DataFrame
    phish_df = pd.DataFrame(data)
    if phish_df.empty:
        print("JSON fetched, but no phishing data returned.", flush=True)
        sys.exit(0)

    # Filter today's verified phishing sites
    today_date = datetime.utcnow().strftime('%Y-%m-%d')
    phish_df['verification_date'] = phish_df['verification_time'].astype(str).str.split('T').str[0]
    phish_df = phish_df[
        (phish_df['verification_date'] == today_date) &
        (phish_df['verified'] == "yes") &
        (phish_df['online'] == "yes")
    ][['url', 'verification_time', 'target']].reset_index(drop=True)
    if phish_df.empty:
        print("DataFrame filtered, but no phishing data returned.", flush=True)
        sys.exit(0)

    # Fetch HTML content
    html_contents = [fetch_html(url) for url in phish_df['url']]
    phish_df['html_content'] = html_contents
    phish_df['html_length'] = phish_df['html_content'].str.len().fillna(0).astype(int)
    phish_df['fetch_status'] = phish_df['html_content'].apply(lambda x: "success" if x else "failed")
    phish_df['fetch_date'] = datetime.utcnow().strftime('%Y-%m-%d')

    # Filter out invalid sites
    phish_df = phish_df[
        (phish_df['fetch_status'] == "success") &
        (phish_df['html_content'] != "<html><head></head><body></body></html>") &
        (phish_df['html_length'] > 6000)
    ]
    print(f"Filtered to {len(phish_df)} valid phishing records.", flush=True)

    # Extract the features
    phish_df = phish_df[['url', 'html_content', 'fetch_date']]
    phish_df['visible_text'] = phish_df['html_content'].apply(extract_text)
    heuristic_features = phish_df.apply(extract_heuristic, axis=1)
    phish_df = pd.concat([phish_df, heuristic_features], axis=1)
    
    # Save locally as CSV
    output_file = f"phish_data_{today_date}.csv"
    phish_df.to_csv(output_file, index=False)
    print(f"Saved {len(phish_df)} phishing records to {output_file}.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Unhandled error: {e}", flush=True)
