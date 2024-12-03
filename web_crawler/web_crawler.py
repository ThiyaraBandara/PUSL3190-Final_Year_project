# Web crawler 
# This should contain a class which uses htmlfetcher to get HTML content from given urls, then it should exrtract the links from a tags 
# Finally it should iteratively visit every found URL until it hits a given depth.

# webcrawler.py

from html_fetcher import HTMLFetcher
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from database_manager import DatabaseManager

class WebCrawler:
    def __init__(self, max_depth):
        self.max_depth = max_depth
        self.html_fetcher = HTMLFetcher()
        self.visited_urls = set()  # To keep track of visited URLs

    def crawl(self, url, depth=0):
        if depth > self.max_depth or url in self.visited_urls:
            return

        print(f"Crawling URL: {url} at depth: {depth}")
        self.visited_urls.add(url)

        html_content = self.html_fetcher.fetch_html(url)
        db_manager = DatabaseManager(host='localhost', user='phishing', password='phishing', database='phishing_detection')
        db_manager.store_html(url, html_content)
        db_manager.close_connection()
        
        if html_content:
            self.extract_links(html_content, url, depth)

    def extract_links(self, html_content, base_url, depth):
        soup = BeautifulSoup(html_content, 'html.parser')
        for link in soup.find_all('a', href=True):
            full_url = urljoin(base_url, link['href'])
            self.crawl(full_url, depth + 1)

# Example usage:
# if __name__ == "__main__":
#     crawler = WebCrawler(max_depth=2)
#     crawler.crawl('http://example.com')