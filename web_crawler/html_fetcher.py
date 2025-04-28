# html_fetcher.py

import requests
from database_manager import DatabaseManager

class HTMLFetcher:
    def fetch_html(self, url):
        try:
            response = requests.get(url)
            response.raise_for_status()  # Raise an error for bad responses
            return response.text
        except requests.exceptions.RetryError as e:
            print(f"Ignored URL {url}: Unresponsive")
            pass
        except requests.RequestException as e:
            print(f"Error fetching {url}: {e}")
            return None