# Web crawler 
# This should contain a class which uses htmlfetcher to get HTML content from given urls, then it should exrtract the links from a tags 
# Finally it should iteratively visit every found URL until it hits a given depth.

# webcrawler.py

from html_fetcher import HTMLFetcher
from phishing_detector import PhishingDetector
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from database_manager import DatabaseManager
from datetime import datetime
import tldextract

class WebCrawler:
    def __init__(self, max_depth):
        self.max_depth = max_depth
        self.html_fetcher = HTMLFetcher()
        self.phishing_detector = PhishingDetector()
        self.visited_urls = set()  # To keep track of visited URLs

    def crawl(self, url, depth=0, dtlinks=[]):
        if depth > self.max_depth or url in self.visited_urls:
            return dtlinks

        print(f"Crawling URL: {url} at depth: {depth}")
        self.visited_urls.add(url)

        html_content = self.html_fetcher.fetch_html(url)
        db_manager = DatabaseManager(host='localhost', user='phishing', password='phishing', database='phishing_detection')
        db_manager.store_urlinfo(url, html_content)

        if (html_content is None):
            return dtlinks
        
        # Detect phishing
        phishing_score = self.phishing_detector.detect_phishing(url, html_content)
        if phishing_score > 0:
            db_manager.store_detected_link(url, phishing_score)
            dtlinks.append({'url': url, 'phishing_score': phishing_score, 'time': datetime.now()})
            print(f"Phishing detected for {url} with score {phishing_score}%")
        
        if html_content:
            self.extract_links(html_content, url, depth, dtlinks)
        
        return dtlinks

    def extract_links(self, html_content, base_url, depth, dtlinks):
        _dtlinks = []
        soup = BeautifulSoup(html_content, 'html.parser')

        # Extract the base domain for filtering
        base_domain_info = tldextract.extract(base_url)
        base_domain = f"{base_domain_info.domain}.{base_domain_info.suffix}"

        for link in soup.find_all('a', href=True):
            full_url = urljoin(base_url, link['href'])
            link_domain_info = tldextract.extract(full_url)
            link_domain = f"{link_domain_info.domain}.{link_domain_info.suffix}"

            # Only crawl links that are from the same domain
            if link_domain == base_domain and link_domain_info.subdomain == '':
                _tmp = self.crawl(full_url, depth + 1, dtlinks)  # Ensure _tmp is assigned here
                if _tmp:  # Check _tmp within the same scope
                    _dtlinks.extend(_tmp)
        
        return _dtlinks