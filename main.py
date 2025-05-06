import asyncio
import requests
from typing import List, Dict
from datetime import datetime, timedelta
from playwright.async_api import async_playwright

import os
import pandas as pd
from supabase import create_client, Client

# ----- HELPER FUNCTIONS ----- #

async def fetch_html(url: str) -> str:
    """Fetch HTML content using async Playwright"""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        try:
            # Set timeout and navigate to page
            page.set_default_timeout(15000)
            await page.goto(url, wait_until="domcontentloaded")

            # Wait for page to settle
            await asyncio.sleep(2)

            # Get the HTML content
            html = await page.content()
            return html
        except:
            return None
        finally:
            await browser.close()

async def fetch_multiple_urls(urls: List[str]) -> List[Dict[str, str]]:
    """Fetch multiple URLs concurrently"""
    tasks = [fetch_html(url) for url in urls]
    return await asyncio.gather(*tasks)

# ----- MAIN ----- #

async def main():
    JSON_URL = "http://data.phishtank.com/data/online-valid.json"
    try:
        response = requests.get(JSON_URL)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from {JSON_URL}: {e}")
        return None

    # Convert JSON data to DataFrame
    phish_df = pd.DataFrame(data)

    # Filter for sites verified yesterday
    yesterday_date = (datetime.utcnow() - timedelta(days=1)).strftime('%Y-%m-%d')
    phish_df['verification_date'] = phish_df['verification_time'].str.split('T').str[0]
    phish_df = phish_df.loc[phish_df['verification_date'] == yesterday_date]
    phish_df = phish_df.loc[phish_df['verified'] == "yes"]
    phish_df = phish_df.loc[phish_df['online'] == "yes"]
    phish_df = phish_df[['url', 'verification_time', 'target']].reset_index(drop=True)

    # Fetch HTML content asynchronously
    phish_df = phish_df.head(100)
    urls = phish_df['url'].tolist()
    html_contents = await fetch_multiple_urls(urls)

    # Add results to DataFrame
    phish_df['html_content'] = html_contents
    phish_df['fetch_status'] = phish_df['html_content'].apply(lambda x: "success" if x else "failed")
    phish_df['fetched_date'] = datetime.utcnow().strftime('%Y-%m-%d')

    # Filter for rows with HTML
    phish_df = phish_df.loc[phish_df['fetch_status'] == "success"]
    phish_df = phish_df.loc[phish_df['html_content'] != "<html><head></head><body></body></html>"]

    # Select columns for database
    output_df = phish_df[['url', 'html_content', 'target', 'verification_time', 'fetched_date']].reset_index(drop=True)

    # Configuration
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY")
    TABLE_NAME = "daily_phish"

    # Initialize Supabase client
    supabase_client: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

    # Upload to Supabase
    records = output_df.to_dict("records")
    response = supabase_client.table(TABLE_NAME).insert(records).execute()
    print(f"Successfully uploaded {len(response.data)} records!")

if __name__ == "__main__":
    asyncio.run(main())
