# Web crawler 

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

    def crawl(self, url, depth=0, dtlinks=None, origin_domain=None):
        # Initialize dtlinks if not provided
        if dtlinks is None:
            dtlinks = []
            
        # Extract domain from URL if origin_domain is not provided
        if origin_domain is None:
            domain_info = tldextract.extract(url)
            origin_domain = f"{domain_info.domain}.{domain_info.suffix}"
            
        # Reset visited_urls for each new origin URL to ensure complete crawling
        if depth == 0:
            self.visited_urls = set()
            
        if depth > self.max_depth or url in self.visited_urls:
            return dtlinks

        print(f"Crawling URL: {url} at depth: {depth}")
        self.visited_urls.add(url)

        html_content = self.html_fetcher.fetch_html(url)
        db_manager = DatabaseManager(host='localhost', user='root', password='123', database='phishing_detection')
        db_manager.store_urlinfo(url, html_content)

        if html_content is None:
            return dtlinks
        
        # Detect phishing
        phishing_score = self.phishing_detector.detect_phishing(url, html_content)
        if phishing_score > 0:
            db_manager.store_detected_link(url, phishing_score)
            dtlinks.append({
                'url': url, 
                'phishing_score': phishing_score, 
                'time': datetime.now(),
                'origin_domain': origin_domain  # Track which domain this belongs to
            })
            print(f"Phishing detected for {url} with score {phishing_score}%")
        
        if html_content:
            self.extract_links(html_content, url, depth, dtlinks, origin_domain)
        
        return dtlinks

    def extract_links(self, html_content, base_url, depth, dtlinks, origin_domain):
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract the domain with subdomains for filtering
        base_domain_info = tldextract.extract(base_url)
        base_domain = f"{base_domain_info.domain}.{base_domain_info.suffix}"
        if (base_domain_info.subdomain != ''):
                base_domain = f"{base_domain_info.subdomain}.{base_domain_info.domain}.{base_domain_info.suffix}"
                pass

        for link in soup.find_all('a', href=True):
            full_url = urljoin(base_url, link['href'])
            # Extract the domain from the link
            link_domain_info = tldextract.extract(full_url)
            link_domain = f"{link_domain_info.domain}.{link_domain_info.suffix}"
            if (link_domain_info.subdomain != ''):
                link_domain = f"{link_domain_info.subdomain}.{link_domain_info.domain}.{link_domain_info.suffix}"
            if link_domain == base_domain:
                self.crawl(full_url, depth + 1, dtlinks, origin_domain)  # Pass the origin_domain

        return dtlinks