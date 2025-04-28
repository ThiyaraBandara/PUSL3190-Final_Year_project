# phishing_detector.py
import re
import whois
import tldextract
import logging
from datetime import datetime, timedelta
from urllib.parse import urlparse
import hashlib

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='phishing_detector.log'
)
logger = logging.getLogger('PhishingDetector')

class PhishingDetector:
    def __init__(self):
        # Expanded list of suspicious terms
        self.suspicious_terms = [
            "login", "banking", "password", "secure", "account", "html", 
            "verification", "verify", "update", "confirm", "alert", "security",
            "authenticate", "session", "expired", "urgent", "suspension",
            "breach", "unauthorized", "access", "ssn", "social", "security",
            "number", "credit", "card", "pin", "credential"
        ]
        self.length_limit = 40
        # Store historical scores to detect significant changes
        self.historical_scores = {}
    
    def detect_phishing(self, url, html_content):
        scores = {}
        total_score = 0
        
        logger.info(f"Analyzing URL: {url}")
        
        # Check for suspicious terms in the URL and HTML content with weighted scoring
        suspicious_term_count = sum(1 for term in self.suspicious_terms if term in url.lower())
        html_term_count = sum(1 for term in self.suspicious_terms if html_content and term in html_content.lower())
        
        # Modified term scoring with higher weights
        term_score = min(25, (suspicious_term_count * 5) + (html_term_count * 1.5))
        scores['suspicious_terms'] = term_score
        total_score += term_score
        logger.info(f"Suspicious terms score: {term_score}")
        
        # Check URL length
        if len(url) > self.length_limit:
            scores['url_length'] = 15
            total_score += 15
            logger.info("URL length: Failed (too long)")
        else:
            scores['url_length'] = 0
            logger.info("URL length: Passed")
        
        # Check for special characters with weighted scoring
        special_char_count = len(re.findall(r'[!@$%^&#*(),?"{}|<>]', url))
        if special_char_count > 0:
            special_char_score = min(15, special_char_count * 3)
            scores['special_chars'] = special_char_score
            total_score += special_char_score
            logger.info(f"Special characters: Failed ({special_char_count} found)")
        else:
            scores['special_chars'] = 0
            logger.info("Special characters: Passed")
            
        # Check if the URL contains an IP address
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            scores['ip_address'] = 15
            total_score += 15
            logger.info("IP address check: Failed (IP found)")
        else:
            scores['ip_address'] = 0
            logger.info("IP address check: Passed")
            
        # Check SSL certificate validity (HTTPS)
        parsed_url = urlparse(url)
        if parsed_url.scheme != "https":
            scores['https'] = 15
            total_score += 15
            logger.info("HTTPS check: Failed (no HTTPS)")
        else:
            # Check for deceptive domains with "secure" in HTTPS URLs
            if any(term in parsed_url.netloc.lower() for term in ['secure', 'banking', 'verify']):
                scores['deceptive_https'] = 10
                total_score += 10
                logger.info("Deceptive HTTPS domain: Failed (contains security terms)")
            else:
                scores['deceptive_https'] = 0
                logger.info("Deceptive HTTPS domain: Passed")
            scores['https'] = 0
            logger.info("HTTPS check: Passed")
            
        # Domain age check with error handling
        try:
            parsed_url = tldextract.extract(url)
            if not parsed_url.domain or not parsed_url.suffix:
                logger.warning("Unable to extract valid domain parts")
                scores['domain_age'] = 15
                total_score += 15
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
                            scores['domain_age'] = 15
                            total_score += 15
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
            
        # Enhanced HTML content analysis
        if html_content:
            # Check for password fields
            password_fields = len(re.findall(r'input[^>]*type=[\'"]password[\'"]', html_content, re.IGNORECASE))
            if password_fields > 0:
                password_score = min(15, password_fields * 7)
                scores['password_fields'] = password_score
                total_score += password_score
                logger.info(f"Password fields check: Failed ({password_fields} found)")
            else:
                scores['password_fields'] = 0
                logger.info("Password fields check: Passed")
                
            # Check for excessive form fields (potential data harvesting)
            form_fields = len(re.findall(r'<input', html_content, re.IGNORECASE))
            if form_fields > 6:
                form_score = min(15, (form_fields - 6) * 2)
                scores['excessive_forms'] = form_score
                total_score += form_score
                logger.info(f"Excessive form fields: Failed ({form_fields} found)")
            else:
                scores['excessive_forms'] = 0
                logger.info("Excessive form fields: Passed")
                
            # Check for hidden elements (common in phishing sites)
            hidden_elements = len(re.findall(r'style=[\'"][^\'"]*(display\s*:\s*none|visibility\s*:\s*hidden)[^\'"]* [\'"]', html_content, re.IGNORECASE))
            if hidden_elements > 0:
                hidden_score = min(10, hidden_elements * 5)
                scores['hidden_elements'] = hidden_score
                total_score += hidden_score
                logger.info(f"Hidden elements check: Failed ({hidden_elements} found)")
            else:
                scores['hidden_elements'] = 0
                logger.info("Hidden elements check: Passed")
            
            # Check for iframes (often used in phishing)
            iframes = len(re.findall(r'<iframe', html_content, re.IGNORECASE))
            if iframes > 0:
                iframe_score = min(10, iframes * 5)
                scores['iframes'] = iframe_score
                total_score += iframe_score
                logger.info(f"Iframe check: Failed ({iframes} found)")
            else:
                scores['iframes'] = 0
                logger.info("Iframe check: Passed")
                
            # Check for urgency language
            urgency_terms = ['urgent', 'immediate', 'alert', 'warning', 'expired', 'suspension', 'limited time', 'security breach']
            urgency_count = sum(1 for term in urgency_terms if term in html_content.lower())
            if urgency_count > 0:
                urgency_score = min(15, urgency_count * 5)
                scores['urgency_language'] = urgency_score
                total_score += urgency_score
                logger.info(f"Urgency language check: Failed ({urgency_count} terms found)")
            else:
                scores['urgency_language'] = 0
                logger.info("Urgency language check: Passed")
                
            # Check for fake security indicators
            security_indicators = len(re.findall(r'secure|verified|protected|ssl|certificate|encrypted', html_content.lower()))
            if security_indicators > 2:
                security_score = min(10, (security_indicators - 2) * 2.5)
                scores['fake_security'] = security_score
                total_score += security_score
                logger.info(f"Fake security indicators: Failed ({security_indicators} found)")
            else:
                scores['fake_security'] = 0
                logger.info("Fake security indicators: Passed")
                
            # Check for sensitive information requests
            sensitive_fields = re.findall(r'ssn|social security|tax id|credit card|cvv|expiration|mother\'s maiden|passport', html_content.lower())
            if sensitive_fields:
                sensitive_score = min(20, len(sensitive_fields) * 10)
                scores['sensitive_info_requests'] = sensitive_score
                total_score += sensitive_score
                logger.info(f"Sensitive info requests: Failed ({len(sensitive_fields)} types found)")
            else:
                scores['sensitive_info_requests'] = 0
                logger.info("Sensitive info requests: Passed")
                
            # Check for countdown timers (urgency creation)
            has_countdown = bool(re.search(r'(countdown|timer|expires|minutes|seconds)', html_content.lower()))
            if has_countdown:
                scores['countdown_timer'] = 10
                total_score += 10
                logger.info("Countdown timer: Failed (detected)")
            else:
                scores['countdown_timer'] = 0
                logger.info("Countdown timer: Passed")
        else:
            logger.warning("No HTML content provided for analysis")
            scores['html_analysis'] = 10
            total_score += 10
        
        # Check URL for brand impersonation
        brand_names = ['paypal', 'apple', 'microsoft', 'amazon', 'facebook', 'google', 'chase', 
                      'wellsfargo', 'bankofamerica', 'citibank', 'instagram', 'netflix']
        found_brands = [brand for brand in brand_names if brand in url.lower()]
        if found_brands:
            brand_score = min(15, len(found_brands) * 5)
            scores['brand_impersonation'] = brand_score
            total_score += brand_score
            logger.info(f"Brand impersonation: Failed ({', '.join(found_brands)} found in URL)")
        else:
            scores['brand_impersonation'] = 0
            logger.info("Brand impersonation: Passed")
        
        # Track score changes over time
        if url in self.historical_scores:
            prev_score = self.historical_scores[url]
            score_change = total_score - prev_score
            if abs(score_change) > 15:
                logger.warning(f"Significant score change detected for {url}: {prev_score} → {total_score}")
        
        self.historical_scores[url] = total_score
        
        # Normalize score if it exceeds 100
        if total_score > 100:
            total_score = 100
            
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
        elif 30 <= score <= 60:
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
    
# If you need to force a specific score for testing, you can use this function
def force_score(url, html_content, target_score=75):
    """
    Analyze a site but force a specific target score for testing purposes
    """
    detector = PhishingDetector()
    actual_score = detector.detect_phishing(url, html_content)
    details = detector.get_last_score_details()
    risk_level, description = detector.get_risk_level(target_score)
    
    # Override with target score
    result = {
        "url": url,
        "original_score": actual_score,
        "score": target_score,  # Forced score
        "risk_level": risk_level,
        "description": description,
        "details": details,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "note": "Score manually adjusted for testing purposes"
    }
    
    logger.info(f"Analysis complete for {url}: {risk_level} (Forced Score: {target_score}, Original: {actual_score})")
    return result