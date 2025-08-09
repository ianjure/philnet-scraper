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


# Fetch phishing data
async def fetch_phish():
    # Step 1: Fetch JSON from PhishTank
    for attempt in range(MAX_RETRIES):
        try:
            print(f"Attempt {attempt + 1}/{MAX_RETRIES} to fetch data...", flush=True)
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
            break
        except Exception as e:
            print(f"Error fetching data: {e}", flush=True)
            traceback.print_exc()
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
            else:
                sys.exit(1)

    phish_df = pd.DataFrame(data)
    if phish_df.empty:
        print("No phishing data found.", flush=True)
        sys.exit(0)

    # Step 2: Filter today's verified phishing sites
    today = datetime.utcnow().strftime('%Y-%m-%d')
    phish_df['verification_date'] = phish_df['verification_time'].astype(str).str.split('T').str[0]
    phish_df = phish_df[
        (phish_df['verification_date'] == today) &
        (phish_df['verified'] == "yes") &
        (phish_df['online'] == "yes")
    ][['url', 'verification_time', 'target']].reset_index(drop=True)

    if phish_df.empty:
        print("No verified phishing data for today.", flush=True)
        sys.exit(0)

    # Step 3: Fetch HTML content
    html_contents = await asyncio.gather(*(fetch_html(url) for url in phish_df['url']))
    phish_df['html_content'] = html_contents
    phish_df['html_length'] = phish_df['html_content'].str.len().fillna(0).astype(int)
    phish_df['fetch_status'] = phish_df['html_content'].apply(lambda x: "success" if x else "failed")
    phish_df['fetch_date'] = today

    # Step 4: Filter valid HTML
    phish_df = phish_df[
        (phish_df['fetch_status'] == "success") &
        (phish_df['html_content'] != "<html><head></head><body></body></html>") &
        (phish_df['html_length'] > 6000)
    ]
    print(f"Filtered to {len(phish_df)} valid phishing records.", flush=True)

    # Step 5: Extract features
    extracted = phish_df.apply(
        lambda row: extract_features(row['url'], row['html_content']),
        axis=1
    )

    phish_df['visible_text'] = [item[0] for item in extracted]
    features_df = pd.DataFrame([item[1] for item in extracted], index=phish_df.index)

    phish_df = pd.concat([phish_df.drop(columns=['html_content']), features_df], axis=1)

    # Step 6: Save locally and upload
    phish_df['result'] = 1 # Label for phish
    phish_df.drop(columns="html_content", inplace=True)
    for col in phish_df.select_dtypes(include=['object', 'string']):
        phish_df[col] = phish_df[col].astype(str).str.encode('utf-8', 'ignore').str.decode('utf-8')

    output_file = "new_phish.parquet"
    phish_df.to_parquet(output_file, engine="pyarrow", index=False)

    try:
        local_path = hf_hub_download(repo_id=REPO_ID, filename=PHISH_FILE, repo_type="dataset")
        df_existing = pd.read_parquet(local_path)
    except Exception:
        df_existing = pd.DataFrame()

    df_combined = pd.concat([df_existing, phish_df], ignore_index=True).drop_duplicates()
    df_combined.to_parquet(PHISH_FILE, engine="pyarrow", index=False)

    login(token=TOKEN)
    upload_file(
        path_or_fileobj=PHISH_FILE,
        path_in_repo=PHISH_FILE,
        repo_id=REPO_ID,
        repo_type="dataset"
    )
    print("Phishing dataset updated successfully!", flush=True)

    return len(phish_df)


# Fetch legitimate data
async def fetch_legit(count):
    def normalize_domain(domain: str) -> str:
        return domain.lower()[4:] if domain.lower().startswith("www.") else domain.lower()

    def get_root_domain(url: str) -> str:
        try:
            domain = urlparse(url).netloc.lower()
            return domain[4:] if domain.startswith("www.") else domain
        except Exception:
            return ""

    # Step 1: Load Tranco
    t = Tranco(cache=True)
    tranco_domains = t.list().top(1_000_000)
    df_tranco = pd.DataFrame(tranco_domains, columns=["domain"])
    df_tranco["domain"] = df_tranco["domain"].apply(normalize_domain)

    # Step 2: Remove already existing domains
    df_dataset = pd.read_csv("dataset_full.csv")
    df_dataset["root_domain"] = df_dataset["url"].apply(get_root_domain)
    existing_domains = set(df_dataset["root_domain"].dropna().unique())
    df_filtered = df_tranco[~df_tranco["domain"].isin(existing_domains)].drop_duplicates()

    async def try_protocols(domain):
        """
        Try fetching HTML over HTTPS and HTTP in parallel.
        Return (working_url, html_content) or (None, None) if both fail.
        """
        async def try_fetch(url):
            html = await fetch_html(url)
            return (url, html) if html else (None, None)
    
        https_task = asyncio.create_task(try_fetch(f"https://{domain}"))
        http_task = asyncio.create_task(try_fetch(f"http://{domain}"))
    
        done, pending = await asyncio.wait(
            {https_task, http_task},
            return_when=asyncio.FIRST_COMPLETED
        )
    
        # Cancel the slower one
        for task in pending:
            task.cancel()
    
        # Get result from the first finished task
        for task in done:
            url, html = await task
            if url and html:
                return url, html
    
        # If the first completed failed, check if the other one succeeded
        for task in pending:
            try:
                url, html = await task
                if url and html:
                    return url, html
            except asyncio.CancelledError:
                pass
    
        return None, None

    # Step 3: Oversample from Tranco
    oversample_factor = 3
    legit_df = df_filtered.head(count * oversample_factor).copy()
    
    # Step 4: Fetch in parallel for all domains
    results = await asyncio.gather(*(try_protocols(domain) for domain in legit_df["domain"]))
    legit_df["url"] = [u for u, _ in results]
    legit_df["html_content"] = [h for _, h in results]
    legit_df["html_length"] = legit_df["html_content"].str.len().fillna(0).astype(int)
    legit_df["fetch_status"] = legit_df["html_content"].apply(lambda x: "success" if x else "failed")
    legit_df["fetch_date"] = datetime.utcnow().strftime('%Y-%m-%d')

    legit_df = legit_df[
        (legit_df['fetch_status'] == "success") &
        (legit_df['html_content'] != "<html><head></head><body></body></html>") &
        (legit_df['html_length'] > 6000)
    ]
    print(f"Filtered to {len(legit_df)} valid legit records.", flush=True)

    # Step 5: Extract features
    extracted = legit_df.apply(
        lambda row: extract_features(row['url'], row['html_content']),
        axis=1
    )

    legit_df['visible_text'] = [item[0] for item in extracted]
    features_df = pd.DataFrame([item[1] for item in extracted], index=legit_df.index)

    legit_df = pd.concat([legit_df.drop(columns=['html_content']), features_df], axis=1)

    # Step 6: Save locally and upload
    legit_df["result"] = 0  # Label for legit
    legit_df.drop(columns="html_content", inplace=True)

    for col in legit_df.select_dtypes(include=['object', 'string']):
        legit_df[col] = legit_df[col].astype(str).str.encode('utf-8', 'ignore').str.decode('utf-8')
    
    output_file = "new_legit.parquet"
    legit_df.to_parquet(output_file, engine="pyarrow", index=False)
    
    try:
        local_path = hf_hub_download(repo_id=REPO_ID, filename=LEGIT_FILE, repo_type="dataset")
        df_existing = pd.read_parquet(local_path)
    except Exception:
        df_existing = pd.DataFrame()

    df_combined = pd.concat([df_existing, legit_df], ignore_index=True).drop_duplicates()
    df_combined.to_parquet(LEGIT_FILE, engine="pyarrow", index=False)
    
    login(token=TOKEN)
    upload_file(
        path_or_fileobj=LEGIT_FILE,
        path_in_repo=LEGIT_FILE,
        repo_id=REPO_ID,
        repo_type="dataset"
    )
    print("Legit dataset updated successfully!", flush=True)

# Main runner
async def main():
    phish_count = await fetch_phish()
    await fetch_legit(phish_count)

if __name__ == "__main__":
    asyncio.run(main())


