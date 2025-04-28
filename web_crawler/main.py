# main.py

from url_input import URLInput
from database_manager import DatabaseManager
from web_crawler import WebCrawler
from phishing_detector import PhishingDetector
from report_generator import ReportGenerator
from datetime import datetime
import tldextract

def main():
    # Initialize classes
    url_input = URLInput()

    # Initialize database manager with your credentials
    db_manager = DatabaseManager(host='localhost', user='root', password='123', database='phishing_detection')

    report_generator = ReportGenerator()
    phishing_detector = PhishingDetector()

    # Get URLs from user
    urls = url_input.get_urls()

    # Create a web crawler with a depth limit
    web_crawler = WebCrawler(max_depth=2)

    # Dictionary to store detected links by origin
    detected_links_by_origin = {}

    # Crawl each URL and store HTML in the database
    for url in urls:
        # Extract domain to use as identifier
        domain_info = tldextract.extract(url)
        origin_domain = f"{domain_info.domain}.{domain_info.suffix}"
        
        print(f"\nProcessing website: {origin_domain} ({url})")
        
        html_content = web_crawler.html_fetcher.fetch_html(url)
        
        if html_content:
            db_manager.store_urlinfo(url, html_content)  # Store the initial URL's HTML content
            
            # Check if the initial URL is phishing
            phishing_score = phishing_detector.detect_phishing(url, html_content)
            
            # Initialize the list for this origin if not already done
            if origin_domain not in detected_links_by_origin:
                detected_links_by_origin[origin_domain] = []
            
            if phishing_score > 0:
                db_manager.store_detected_link(url, phishing_score)
                detected_links_by_origin[origin_domain].append({
                    'url': url, 
                    'phishing_score': phishing_score, 
                    'time': datetime.now(),
                    'origin_domain': origin_domain
                })
                print(f"Phishing detected for {url} with score {phishing_score}%")
            
            # Start crawling from the initial URL, tracking the origin domain
            crawled_links = web_crawler.crawl(url, origin_domain=origin_domain)
            
            # Add crawled links to the appropriate origin
            for link in crawled_links:
                link_origin = link['origin_domain']
                if link_origin not in detected_links_by_origin:
                    detected_links_by_origin[link_origin] = []
                detected_links_by_origin[link_origin].append(link)
    
    # Generate and print the report
    report_file = report_generator.generate_report(detected_links_by_origin)
    print(f"Your report has been generated at {report_file}")
    
    # Close database connection
    db_manager.close_connection()

if __name__ == "__main__":
    main()