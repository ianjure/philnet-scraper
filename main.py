import os
import sys
import time

from utils import fetch_html, extract_features

import traceback
import pandas as pd
from datetime import datetime

from huggingface_hub import hf_hub_download, login, upload_file

# Initialize data fetching configuration variables
JSON_URL = "http://data.phishtank.com/data/online-valid.json"
max_retries = 5
retry_delay = 600

# Initialize Hugging Face repository variables
repo_id = "ianjure/philnet"
parquet_file = "phish.parquet"
token = os.getenv("HUGGINGFACE_TOKEN")

# Main function to fetch data
def main():
    for attempt in range(max_retries): # Fetch JSON data
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
    phish_df = phish_df[['url', 'html_content']]
    phish_df['visible_text'] = phish_df['html_content'].apply(extract_texts)
    heuristic_features = phish_df.apply(extract_heuristics, axis=1)
    phish_df = pd.concat([phish_df, heuristic_features], axis=1)

    # Save as parquet file
    phish_df['result'] = 1
    phish_df = phish_df.drop(columns="html_content")
    
    for col in phish_df.select_dtypes(include=['object', 'string']):
        phish_df[col] = phish_df[col].astype(str).str.encode('utf-8', 'ignore').str.decode('utf-8')

    output_file = "new_phish.parquet"
    phish_df.to_parquet(output_file, engine="pyarrow", index=False)
    print(f"Saved {len(phish_df)} phishing records to {output_file}.")

    # Save to database
    try:
        local_path = hf_hub_download(
            repo_id=repo_id,
            filename=parquet_file,
            repo_type="dataset"
        )
        print(f"Downloaded {parquet_file} to {local_path}", flush=True)
        df_existing = pd.read_parquet(local_path)
        print(f"Loaded {len(df_existing)} existing records.", flush=True)
    except Exception:
        print("No existing Parquet found. Creating a new one.", flush=True)
        df_existing = pd.DataFrame()
        
    df_combined = pd.concat([df_existing, phish_df], ignore_index=True)
    df_combined.drop_duplicates(inplace=True)
    print(f"Combined total records: {len(df_combined)}", flush=True)

    df_combined.to_parquet(parquet_file, engine="pyarrow", index=False)
    print(f"Saved updated dataset to {parquet_file}", flush=True)

    login(token=token)
    upload_file(
        path_or_fileobj=parquet_file,
        path_in_repo=parquet_file,
        repo_id=repo_id,
        repo_type="dataset"
    )
    print("Phishing records updated successfully!", flush=True)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Unhandled error: {e}", flush=True)


