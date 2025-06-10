import os
import sys
import time
import asyncio
import requests
import traceback
import pandas as pd
from asyncio import Semaphore
from typing import List, Dict
from datetime import datetime
from supabase import create_client, Client
from playwright.async_api import async_playwright

# ----- CONFIGURATION ----- #

JSON_URL = "http://data.phishtank.com/data/online-valid.json"
max_retries = 5 
retry_delay = 600
sem = Semaphore(5)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase_client: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
TABLE_NAME = "phish_data"

# ----- HELPER FUNCTIONS ----- #

async def fetch_html(context, url: str) -> str:
    """Fetch HTML content using async Playwright"""
    async with sem:
        try:
            page = await context.new_page()
            await page.goto(url, wait_until="networkidle", timeout=20000)
            html = await page.content()
            await page.close()
            return html
        except Exception as e:
            print(f"Error fetching {url}: {e}")
            return None

async def fetch_multiple_urls(playwright, urls: List[str]) -> List[str]:
    """Fetch multiple URLs concurrently"""
    browser = await playwright.chromium.launch(headless=True)
    context = await browser.new_context()
    try:
        tasks = [fetch_html(context, url) for url in urls]
        return await asyncio.gather(*tasks)
    finally:
        await browser.close()

# ----- MAIN FUNCTION ----- #

async def main():
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
                traceback.print_exc()
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
    urls = phish_df['url'].tolist()
    async with async_playwright() as p:
        html_contents = await fetch_multiple_urls(p, urls)
    print(f"Fetched HTML content for {len(html_contents)} URLs.", flush=True)

    # Add results to DataFrame
    phish_df['html_content'] = html_contents
    phish_df['html_length'] = phish_df['html_content'].str.len().fillna(0).astype(int)
    phish_df['fetch_status'] = phish_df['html_content'].apply(lambda x: "success" if x else "failed")
    phish_df['fetched_date'] = datetime.utcnow().strftime('%Y-%m-%d')

    # Filter out invalid HTML
    phish_df = phish_df[
        (phish_df['fetch_status'] == "success") &
        (phish_df['html_content'] != "<html><head></head><body></body></html>") &
        (phish_df['html_length'] > 5000)
    ]
    print(f"Filtered to {len(phish_df)} valid phishing records.", flush=True)

    # Upload to Supabase
    output_df = phish_df[['url', 'html_content', 'html_length', 'verification_time', 'fetched_date']]
    records = output_df.to_dict("records")
    if records:
        response = supabase_client.table(TABLE_NAME).insert(records).execute()
        print(f"Successfully uploaded {len(response.data)} records!", flush=True)
    else:
        print("No valid phishing records to upload today.", flush=True)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"Unhandled error: {e}", flush=True)
