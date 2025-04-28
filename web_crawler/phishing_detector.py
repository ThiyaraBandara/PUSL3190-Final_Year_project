# phishing_detector.py
import re
import whois
import tldextract
import logging
from datetime import datetime, timedelta
from urllib.parse import urlparse

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='phishing_detector.log'
)
logger = logging.getLogger('PhishingDetector')

class PhishingDetector:
    def __init__(self):
        self.suspicious_terms = ["login", "banking", "password", "secure", "account", "html", "verification", "verify", "update"]
        self.length_limit = 40
        # Store historical scores to detect significant changes
        self.historical_scores = {}
    
    def detect_phishing(self, url, html_content):
        scores = {}
        total_score = 0
        
        logger.info(f"Analyzing URL: {url}")
        
        # Check for suspicious terms in the URL and HTML content
        suspicious_term_count = sum(1 for term in self.suspicious_terms if term in url.lower())
        html_term_count = sum(1 for term in self.suspicious_terms if html_content and term in html_content.lower())
        
        term_score = min(20, (suspicious_term_count * 5) + (html_term_count * 2))
        scores['suspicious_terms'] = term_score
        total_score += term_score
        logger.info(f"Suspicious terms score: {term_score}")
        
        # Check URL length
        if len(url) > self.length_limit:
            scores['url_length'] = 20
            total_score += 20
            logger.info("URL length: Failed (too long)")
        else:
            scores['url_length'] = 0
            logger.info("URL length: Passed")
        
        # Check for special characters
        special_char_count = len(re.findall(r'[!@$%^&#*(),?"{}|<>]', url))
        if special_char_count > 0:
            special_char_score = min(20, special_char_count * 4)
            scores['special_chars'] = special_char_score
            total_score += special_char_score
            logger.info(f"Special characters: Failed ({special_char_count} found)")
        else:
            scores['special_chars'] = 0
            logger.info("Special characters: Passed")
            
        # Check if the URL contains an IP address
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            scores['ip_address'] = 20
            total_score += 20
            logger.info("IP address check: Failed (IP found)")
        else:
            scores['ip_address'] = 0
            logger.info("IP address check: Passed")
            
        # Check SSL certificate validity (HTTPS)
        parsed_url = urlparse(url)
        if parsed_url.scheme != "https":
            scores['https'] = 20
            total_score += 20
            logger.info("HTTPS check: Failed (no HTTPS)")
        else:
            scores['https'] = 0
            logger.info("HTTPS check: Passed")
            
        # Domain age check with error handling
        try:
            parsed_url = tldextract.extract(url)
            if not parsed_url.domain or not parsed_url.suffix:
                logger.warning("Unable to extract valid domain parts")
                scores['domain_age'] = 20
                total_score += 20
            else:
                parsed_domain = f"{parsed_url.domain}.{parsed_url.suffix}"
                try:
                    domain_info = whois.whois(parsed_domain)
                    
                    if domain_info.creation_date:
                        if isinstance(domain_info.creation_date, list):
                            creation_date = domain_info.creation_date[0]
                        else:
                            creation_date = domain_info.creation_date
                            
                        age = (datetime.now() - creation_date).days
                        if age < 30:  # Less than 1 month old
                            scores['domain_age'] = 20
                            total_score += 20
                            logger.info(f"Domain age check: Failed (domain is {age} days old)")
                        else:
                            scores['domain_age'] = 0
                            logger.info(f"Domain age check: Passed (domain is {age} days old)")
                    else:
                        logger.warning("No creation date found in WHOIS data")
                        scores['domain_age'] = 10  # Partial penalty when data is missing
                        total_score += 10
                except Exception as e:
                    logger.error(f"WHOIS lookup error: {str(e)}")
                    scores['domain_age'] = 10  # Partial penalty on error
                    total_score += 10
        except Exception as e:
            logger.error(f"Domain extraction error: {str(e)}")
            scores['domain_age'] = 10
            total_score += 10
            
        # Check for suspicious HTML elements with better pattern matching
        if html_content:
            # Check for password fields
            password_fields = len(re.findall(r'input[^>]*type=[\'"]password[\'"]', html_content, re.IGNORECASE))
            if password_fields > 0:
                password_score = min(20, password_fields * 10)
                scores['password_fields'] = password_score
                total_score += password_score
                logger.info(f"Password fields check: Failed ({password_fields} found)")
            else:
                scores['password_fields'] = 0
                logger.info("Password fields check: Passed")
                
            # Check for excessive form fields (potential data harvesting)
            form_fields = len(re.findall(r'<input', html_content, re.IGNORECASE))
            if form_fields > 10:
                form_score = min(15, (form_fields - 10) * 1.5)
                scores['excessive_forms'] = form_score
                total_score += form_score
                logger.info(f"Excessive form fields: Failed ({form_fields} found)")
            else:
                scores['excessive_forms'] = 0
                logger.info("Excessive form fields: Passed")
        else:
            logger.warning("No HTML content provided for analysis")
            scores['html_analysis'] = 10
            total_score += 10
        
        # Track score changes over time
        if url in self.historical_scores:
            prev_score = self.historical_scores[url]
            score_change = total_score - prev_score
            if abs(score_change) > 15:
                logger.warning(f"Significant score change detected for {url}: {prev_score} → {total_score}")
        
        self.historical_scores[url] = total_score
        
        # Log detailed score breakdown
        logger.info(f"Total phishing score: {total_score}")
        logger.info(f"Score breakdown: {scores}")
        
        # Store the detailed scores for later retrieval if needed
        self._last_score_details = scores
        
        # Return only the total_score to maintain backward compatibility
        return total_score
    
    def get_last_score_details(self):
        """Return the detailed breakdown of the last phishing score calculation"""
        return getattr(self, '_last_score_details', {})
    
    def get_risk_level(self, score):
        if score < 30:
            return "Safe", "This website appears to be legitimate"
        elif score > 70:
            return "Suspicious", "This website shows some suspicious characteristics"
        else:
            return "Phishing", "This website is likely a phishing attempt"


# Example usage in a crawler
def analyze_website(url, html_content):
    detector = PhishingDetector()
    score = detector.detect_phishing(url, html_content)
    details = detector.get_last_score_details()
    risk_level, description = detector.get_risk_level(score)
    
    result = {
        "url": url,
        "score": score,
        "risk_level": risk_level,
        "description": description,
        "details": details,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    logger.info(f"Analysis complete for {url}: {risk_level} (Score: {score})")
    return result