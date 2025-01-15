# report_generator.py
from fpdf import FPDF
from datetime import datetime

class ReportGenerator:
    def __init__(self):
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)
        # Add Arial font for unicode support
        self.pdf.add_font('Arial', '', 'fonts/Arial.ttf', uni=True)
        
    def generate_report(self, detected_links):
        # Add a page
        self.pdf.add_page()
        
        # Set font for title
        self.pdf.set_font('Arial', 'B', 16)
        self.pdf.cell(0, 10, 'Phishing Detection Report', ln=True, align='C')
        
        # Add timestamp
        self.pdf.set_font('Arial', '', 10)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.pdf.cell(0, 10, f'Generated on: {timestamp}', ln=True, align='R')
        
        # Add separator line
        self.pdf.line(10, self.pdf.get_y(), 200, self.pdf.get_y())
        self.pdf.ln(10)
        
        # Add summary
        self.pdf.set_font('Arial', 'B', 12)
        self.pdf.cell(0, 10, f'Total URLs analyzed: {len(detected_links)}', ln=True)
        
        # Add table headers
        self.pdf.set_font('Arial', 'B', 11)
        self.pdf.cell(140, 10, 'URL', 1, 0)
        self.pdf.cell(50, 10, 'Phishing Score', 1, 1, 'C')
        
        # Add table content
        self.pdf.set_font('Arial', '', 10)
        for link in detected_links:
            # Calculate score color (red for high risk, green for low risk)
            score = float(link['phishing_score'])
            if score >= 70:
                self.pdf.set_text_color(255, 0, 0)  # Red
            elif score <= 30:
                self.pdf.set_text_color(0, 128, 0)  # Green
            else:
                self.pdf.set_text_color(0, 0, 0)    # Black
            
            # Write URL (with word wrap if needed)
            self.pdf.cell(140, 10, str(link['url'])[:80], 1, 0)
            self.pdf.cell(50, 10, f"{score}", 1, 1, 'C')
            
        # Reset text color
        self.pdf.set_text_color(0, 0, 0)
        
        # Add footer with analysis criteria
        self.pdf.ln(10)
        self.pdf.set_font('Arial', 'B', 11)
        self.pdf.cell(0, 10, 'Analysis Criteria:', ln=True)
        self.pdf.set_font('Arial', '', 10)
        self.pdf.multi_cell(0, 10, 
            '- High Risk (Red): Score >= 70%\n'
            '- Medium Risk (Black): Score between 30% and 70%\n'
            '- Low Risk (Green): Score <= 30%'
        )
        
        # Save the report
        filename = f'reports/phishing_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        self.pdf.output(filename)
        return filename
    
    def print_to_console(self, detected_links):
        report = "Phishing Detection Report\n"
        report += "=" * 30 + "\n"
        for link in detected_links:
            report += f"URL: {link['url']}, Phishing Score: {link['phishing_score']}\n"
        return report
    
