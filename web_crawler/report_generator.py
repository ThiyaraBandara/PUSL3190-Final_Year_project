# report_generator.py

class ReportGenerator:
    def generate_report(self, detected_links):
        report = "Phishing Detection Report\n"
        report += "=" * 30 + "\n"
        for link in detected_links:
            report += f"URL: {link['url']}, Phishing Score: {link['phishing_score']}\n"
        return report
    