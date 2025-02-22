# main.py

from url_input import URLInput
from database_manager import DatabaseManager
from web_crawler import WebCrawler
from phishing_detector import PhishingDetector
from report_generator import ReportGenerator
from datetime import datetime

def main():
    # Initialize classes
    url_input = URLInput()

    # Initialize database manager with your credentials
    db_manager = DatabaseManager(host='localhost', user='phishing', password='phishing', database='phishing_detection')

    report_generator = ReportGenerator()
    phishing_detector = PhishingDetector()

    # Get URLs from user
    urls = url_input.get_urls()

   # Create a web crawler with a depth limit
    web_crawler = WebCrawler(max_depth=2)

    detected_links = []
    detected_links_crawled = []
    # Crawl each URL and store HTML in the database
    for url in urls:
        html_content = web_crawler.html_fetcher.fetch_html(url)
        
        if html_content:
            db_manager.store_urlinfo(url, html_content)  # Store the initial URL's HTML content
            phishing_score = phishing_detector.detect_phishing(url, html_content)
            if phishing_score > 0:
                # Test Case: http://bank.phishing.web.test.dev.asia.south.localtest.me
                db_manager.store_detected_link(url, phishing_score)
                detected_links.append({'url': url, 'phishing_score': phishing_score, 'time': datetime.now()})
                print(f"Phishing detected for {url} with score {phishing_score}%")
            detected_links_crawled = web_crawler.crawl(url)  # Start crawling from the initial URL
            # Generate and print the report
    
    detected_links.extend(detected_links_crawled)
    report_file = report_generator.generate_report(detected_links)
    print(f"Your report has been generated at {report_file}")
    
    # Close database connection
    db_manager.close_connection()

if __name__ == "__main__":
    main()




    # Instead of implementing html_fether here, implement the web_crawler class here.
    # Then, implement a function which uses the html_fether to grab the a tag links from the HTML
    # Finally, visit all the links iteratively and do the same until you reach the depth limit
    # 
    # webcr