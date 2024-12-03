# phishing_detector.py

import re
import whois
import tldextract
from datetime import datetime

class PhishingDetector:
    def __init__(self):
        self.suspicious_terms = ["login", "banking", "password", "secure", "account"]
        self.length_limit = 75

    def detect_phishing(self, url, html_content):
        phishing_score = 0

        # Check for suspicious terms in the URL
        if any(term in url for term in self.suspicious_terms):
            phishing_score += 20

        # Check URL length
        if len(url) > self.length_limit:
            phishing_score += 20

        # Check for special characters
        if re.search(r'[!@#$%^&*(),?":{}|<>]', url):
            phishing_score += 20

        # Check if the URL contains an IP address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', url):
            phishing_score += 20

        # Check SSL certificate validity (HTTPS)
        if not url.startswith("https://"):
            phishing_score += 20

        # Domain age check
        parsed_url = tldextract.extract(url)
        parsed_domain = f"{parsed_url.domain}.{parsed_url.suffix}"
        domain_info = whois.whois(parsed_domain)
        if domain_info.creation_date:
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            age = (datetime.now() - creation_date).days
            if age < 30:  # Less than 1 month old
                phishing_score += 20

        # Check for suspicious HTML elements in the content
        if "input type='password'" in html_content:
            phishing_score += 20

        return phishing_score