# report_generator.py
from fpdf import FPDF
from datetime import datetime
import os
from email_sender import send_email  # Import the send_email function

class ReportGenerator:
    def __init__(self):
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)
        # Add Arial font for unicode support
        self.pdf.add_font('Arial', '', 'fonts/Arial.ttf', uni=True)
        
    def generate_report(self, detected_links):
        # Prompt for recipient email address
        receiver_email = input("Please enter the recipient's email address: ")

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

        # Initialize counters for summary
        phishing_count = 0
        medium_count = 0
        safe_count = 0
        total_score = 0  # Initialize total score for average calculation

        # Add table content
        self.pdf.set_font('Arial', '', 10)
        for link in detected_links:
            # Calculate score color (red for high risk, green for low risk)
            score = float(link['phishing_score'])
            total_score += score  # Accumulate total score

            if score >= 70:
                self.pdf.set_text_color(255, 0, 0)  # Red
                phishing_count += 1
            elif score <= 30:
                self.pdf.set_text_color(0, 128, 0)  # Green
                safe_count += 1
            else:
                self.pdf.set_text_color(0, 0, 0)    # Black
                medium_count += 1
            
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

        # Calculate average score
        total_count = phishing_count + medium_count + safe_count
        average_score = total_score / total_count if total_count > 0 else 0

        # Add summary section
        self.pdf.ln(10)
        self.pdf.set_font('Arial', 'B', 12)
        self.pdf.cell(0, 10, 'Summary:', ln=True)


        
       
        # Determine the summary based on the average score
        if average_score >= 70:
            summary_text = "Detected as a phishing site."
        elif average_score <= 30:
            summary_text = "Not a phishing site."
        else:
            summary_text = "May be a phishing site (mixed results)."

        self.pdf.set_font('Arial', '', 10)
        self.pdf.multi_cell(0, 10, summary_text)

        # Display the average score
        self.pdf.ln(10)  # Add some space before the average score
        self.pdf.set_font('Arial', 'B', 12)
        self.pdf.cell(0, 10, 'Average Phishing Score:', ln=True)
        
        self.pdf.set_font('Arial', '', 10)
        self.pdf.cell(0, 10, f"{average_score:.2f}", ln=True)  # Display average score formatted to 2 decimal places

        # Show calculation details
        self.pdf.set_font('Arial', '', 10)
        if total_count > 0:
            self.pdf.cell(0, 10, f"Total Score: {total_score} / Total Count: {total_count} = Average Score: {average_score:.2f}", ln=True)
        else:
            self.pdf.cell(0, 10, "No URLs analyzed to calculate average score.", ln=True)
        
        # Save the report
        filename = f'reports/phishing_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        self.pdf.output(filename)



        # Send the report via email
        send_email(filename, receiver_email)


        return filename
    


    
    def print_to_console(self, detected_links):
        report = "Phishing Detection Report\n"
        report += "=" * 30 + "\n"
        for link in detected_links:
            report += f"URL: {link['url']}, Phishing Score: {link['phishing_score']}\n"
        return report