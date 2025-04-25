import os
import requests
import pandas as pd
from supabase import create_client, Client
from datetime import datetime, timedelta

def main():
    # Configuration
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY")
    TABLE_NAME = "daily_phish"

    # Initialize Supabase client
    supabase_client: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

    # URL to fetch JSON data from PhishTank
    JSON_URL = "http://data.phishtank.com/data/online-valid.json"

    # Fetch JSON data
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
    phish_df = phish_df[['url', 'verification_time', 'target']]

    # Add fetched_date column
    phish_df['fetched_date'] = datetime.utcnow().strftime('%Y-%m-%d')

    # Upload to Supabase
    records = phish_df.to_dict("records")
    response = supabase_client.table(TABLE_NAME).insert(records).execute()
    print(f"Successfully uploaded {len(response.data)} records!")

if __name__ == "__main__":
    main()