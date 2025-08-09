import os
import sys
import time
import asyncio
import traceback
from datetime import datetime
from urllib.parse import urlparse

import pandas as pd
import requests
from huggingface_hub import hf_hub_download, login, upload_file
from tranco import Tranco

from utils import fetch_html, extract_features


# Config
JSON_URL = "http://data.phishtank.com/data/online-valid.json"
MAX_RETRIES = 5
RETRY_DELAY = 600

REPO_ID = "ianjure/philnet"
PHISH_FILE = "phish.parquet"
LEGIT_FILE = "legit.parquet"
TOKEN = os.getenv("HUGGINGFACE_TOKEN")


# ---------- Helpers ----------

def safe_request_json(url):
    """Fetch JSON with retries."""
    for attempt in range(MAX_RETRIES):
        try:
            print(f"Fetching: attempt {attempt + 1}/{MAX_RETRIES}", flush=True)
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/114.0.0.0 Safari/537.36"
                )
            }
            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            print(f"Error: {e}", flush=True)
            traceback.print_exc()
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
    sys.exit(1)


def extract_features_once(df):
    """Extract visible text and features in one HTML parse per row."""
    extracted = df.apply(lambda row: extract_features(row['url'], row['html_content']), axis=1)
    df['visible_text'] = [item[0] for item in extracted]
    features_df = pd.DataFrame([item[1] for item in extracted], index=df.index)
    return pd.concat([df.drop(columns=['html_content']), features_df], axis=1)


def save_and_upload(df, output_file, repo_filename):
    """Save dataset locally and upload to HF."""
    # Encode safely
    for col in df.select_dtypes(include=['object', 'string']):
        df[col] = df[col].astype(str).str.encode('utf-8', 'ignore').str.decode('utf-8')

    df.to_parquet(output_file, engine="pyarrow", index=False)

    # Merge with existing if available
    try:
        local_path = hf_hub_download(repo_id=REPO_ID, filename=repo_filename, repo_type="dataset")
        df_existing = pd.read_parquet(local_path)
    except Exception:
        df_existing = pd.DataFrame()

    df_combined = pd.concat([df_existing, df], ignore_index=True).drop_duplicates()
    df_combined.to_parquet(repo_filename, engine="pyarrow", index=False)

    login(token=TOKEN)
    upload_file(path_or_fileobj=repo_filename, path_in_repo=repo_filename,
                repo_id=REPO_ID, repo_type="dataset")


# ---------- Main Functions ----------

async def fetch_phish():
    # Step 1: Download & filter
    data = safe_request_json(JSON_URL)
    phish_df = pd.DataFrame(data)
    if phish_df.empty:
        print("No phishing data found.")
        sys.exit(0)

    today = datetime.utcnow().strftime('%Y-%m-%d')
    phish_df['verification_date'] = phish_df['verification_time'].astype(str).str.split('T').str[0]
    phish_df = phish_df[
        (phish_df['verification_date'] == today) &
        (phish_df['verified'] == "yes") &
        (phish_df['online'] == "yes")
    ][['url', 'verification_time', 'target']].reset_index(drop=True)

    if phish_df.empty:
        print("No verified phishing data for today.")
        sys.exit(0)

    # Step 2: Fetch HTML
    phish_df['html_content'] = await asyncio.gather(*(fetch_html(url) for url in phish_df['url']))
    phish_df['html_length'] = phish_df['html_content'].str.len().fillna(0).astype(int)
    phish_df['fetch_status'] = phish_df['html_content'].apply(lambda x: "success" if x else "failed")
    phish_df['fetch_date'] = today

    phish_df = phish_df[
        (phish_df['fetch_status'] == "success") &
        (phish_df['html_content'] != "<html><head></head><body></body></html>") &
        (phish_df['html_length'] > 6000)
    ]
    print(f"Filtered to {len(phish_df)} phishing records.")

    # Step 3: Extract features in one pass
    phish_df = extract_features_once(phish_df)
    phish_df['result'] = 1

    # Step 4: Save & upload
    save_and_upload(phish_df, "new_phish.parquet", PHISH_FILE)
    print("Phishing dataset updated successfully!")
    return len(phish_df)


async def fetch_legit(count):
    def normalize_domain(d): return d.lower()[4:] if d.lower().startswith("www.") else d.lower()
    def root_domain(url):
        try:
            netloc = urlparse(url).netloc.lower()
            return netloc[4:] if netloc.startswith("www.") else netloc
        except Exception:
            return ""

    # Step 1: Tranco list
    tranco_domains = pd.DataFrame(Tranco(cache=True).list().top(1_000_000), columns=["domain"])
    tranco_domains["domain"] = tranco_domains["domain"].apply(normalize_domain)

    # Step 2: Remove already-seen domains
    df_dataset = pd.read_csv("dataset_full.csv")
    df_dataset["root_domain"] = df_dataset["url"].apply(root_domain)
    existing = set(df_dataset["root_domain"].dropna().unique())
    df_filtered = tranco_domains[~tranco_domains["domain"].isin(existing)].drop_duplicates()

    # Step 3: Oversample and fetch
    oversample_factor = 3
    legit_df = df_filtered.head(count * oversample_factor).copy()

    async def try_protocols(domain):
        async def try_fetch(url):
            html = await fetch_html(url)
            return (url, html) if html else (None, None)
        https_task = asyncio.create_task(try_fetch(f"https://{domain}"))
        http_task = asyncio.create_task(try_fetch(f"http://{domain}"))
        done, pending = await asyncio.wait({https_task, http_task}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending: task.cancel()
        for task in done:
            url, html = await task
            if url and html:
                return url, html
        return None, None

    results = await asyncio.gather(*(try_protocols(d) for d in legit_df["domain"]))
    legit_df["url"], legit_df["html_content"] = zip(*results)
    legit_df['html_length'] = legit_df['html_content'].str.len().fillna(0).astype(int)
    legit_df['fetch_status'] = legit_df['html_content'].apply(lambda x: "success" if x else "failed")
    legit_df['fetch_date'] = datetime.utcnow().strftime('%Y-%m-%d')

    legit_df = legit_df[
        (legit_df['fetch_status'] == "success") &
        (legit_df['html_content'] != "<html><head></head><body></body></html>") &
        (legit_df['html_length'] > 6000)
    ]
    print(f"Filtered to {len(legit_df)} legit records.")

    # Step 4: Extract features once
    legit_df = extract_features_once(legit_df)
    legit_df['result'] = 0

    # Step 5: Save & upload
    save_and_upload(legit_df, "new_legit.parquet", LEGIT_FILE)
    print("Legit dataset updated successfully!")


# Runner
async def main():
    phish_count = await fetch_phish()
    await fetch_legit(phish_count)

if __name__ == "__main__":
    asyncio.run(main())
