# report_generator.py
from fpdf import FPDF
from datetime import datetime
import os
from email_sender import send_email  # Import the send_email function
import matplotlib.pyplot as plt
import numpy as np
from io import BytesIO
import matplotlib.patches as mpatches
import tempfile

class ReportGenerator:
    def __init__(self):
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)
        self.pdf.add_font('Arial', '', 'fonts/Arial.ttf', uni=True)

    def generate_risk_chart(self, detected_links_by_origin):
        # Create figure and axis
        plt.figure(figsize=(10, 6))
        
        # Prepare data for the chart
        domains = []
        avg_scores = []
        
        for domain, links in detected_links_by_origin.items():
            if links:  # Only process if there are links
                try:
                    # Calculate average score for this domain
                    avg_score = sum(float(link.get('phishing_score', 0)) for link in links) / len(links)
                    domains.append(domain)
                    avg_scores.append(avg_score)
                except Exception as e:
                    print(f"Error calculating average score for {domain}: {e}")
        
        # Sort domains by average score in descending order
        sorted_data = sorted(zip(domains, avg_scores), key=lambda x: x[1], reverse=True)
        domains = [x[0] for x in sorted_data]
        avg_scores = [x[1] for x in sorted_data]
        
        # Set up the bar chart
        x = np.arange(len(domains))
        
        # Add shaded area for medium risk (drawn first, behind bars)
        plt.axhspan(30, 70, facecolor='gray', alpha=0.15, label='Medium Risk Range (30%-70%)', zorder=0)
        # Create bars with color based on score (drawn above background)
        bars = plt.bar(x, avg_scores, width=0.6, zorder=2)
        
        # Color the bars based on risk level
        for i, score in enumerate(avg_scores):
            if score >= 70:
                bars[i].set_color('red')
            elif score <= 30:
                bars[i].set_color('green')
            else:
                bars[i].set_color('black')
        
        # Customize the chart
        plt.xlabel('Websites')
        plt.ylabel('Average Phishing Score (%)')
        plt.title('Average Phishing Risk by Website')
        
        # Rotate x-axis labels for better readability
        plt.xticks(x, domains, rotation=45, ha='right')
        
        # Add threshold lines (drawn above background, below bars)
        high_line = plt.axhline(y=70, color='red', linestyle='--', alpha=0.3, label='High Risk Threshold', zorder=1)
        low_line = plt.axhline(y=30, color='green', linestyle='--', alpha=0.3, label='Low Risk Threshold', zorder=1)
        
        # Add value labels on top of each bar
        for i, v in enumerate(avg_scores):
            plt.text(i, v + 1, f'{v:.1f}%', ha='center', va='bottom')
        
        # Custom legend patches
        medium_patch = mpatches.Patch(color='gray', alpha=0.15, label='Medium Risk Range (30%-70%)')
        high_patch = mpatches.Patch(color='red', alpha=0.3, label='High Risk Threshold')
        low_patch = mpatches.Patch(color='green', alpha=0.3, label='Low Risk Threshold')
        
        plt.legend(handles=[medium_patch, high_patch, low_patch], loc='best')
        
        # Set y-axis limits to ensure all bars and labels are visible
        plt.ylim(0, max(avg_scores) + 10)
        
        plt.tight_layout()
        
        # Save the chart to a BytesIO object
        img_data = BytesIO()
        plt.savefig(img_data, format='png', dpi=300, bbox_inches='tight')
        img_data.seek(0)
        plt.close()
        
        return img_data

    def generate_report(self, detected_links_by_origin):
        # Debug: Print the structure to console
        print("Report data structure:")
        for domain, links in detected_links_by_origin.items():
            print(f"Domain: {domain}, Number of links: {len(links)}")
        
        # Prompt for recipient email address
        receiver_email = input("Please enter the recipient's email address: ").strip()

        # Add a page
        self.pdf.add_page()
        
        # Set font for title
        self.pdf.set_font('Arial', 'B', 16)
        self.pdf.cell(0, 10, 'Phishing Detection Report', ln=True, align='C')
        
        # Add timestamp
        self.pdf.set_font('Arial', '', 10)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.pdf.cell(0, 10, f'Generated on: {timestamp}', ln=True, align='R')
        
        # Add explanation of risk levels (Analysis Criteria) at the top
        self.pdf.ln(5)
        self.pdf.set_font('Arial', 'B', 12)
        self.pdf.cell(0, 10, 'Analysis Criteria:', ln=True)
        self.pdf.set_font('Arial', '', 10)
        self.pdf.multi_cell(0, 10, 
            '- High Risk (Red): Score >= 70%\n'
            '- Medium Risk (Black): Score between 30% and 70%\n'
            '- Low Risk (Green): Score <= 30%'
        )
        
        # Check if we have any data
        if not detected_links_by_origin:
            self.pdf.ln(20)
            self.pdf.set_font('Arial', 'B', 12)
            self.pdf.cell(0, 10, 'No phishing links were detected.', ln=True, align='C')
            # Save empty report and return
            filename = f'reports/phishing_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            self.pdf.output(filename)
            if receiver_email:
                send_email(filename, receiver_email)
            print(f"Your report has been generated at {filename}")
            return filename
        
        # Count total websites and URLs analyzed
        total_websites = len(detected_links_by_origin)
        total_urls = sum(len(links) for links in detected_links_by_origin.values())
        
        # Add separator line
        self.pdf.line(10, self.pdf.get_y(), 200, self.pdf.get_y())
        self.pdf.ln(10)
        
        # Add summary
        self.pdf.set_font('Arial', 'B', 12)
        self.pdf.cell(0, 10, f'Total Websites analyzed: {total_websites}', ln=True)
        self.pdf.cell(0, 10, f'Total URLs analyzed: {total_urls}', ln=True)
        self.pdf.ln(5)
        
        # Global summary table for quick overview
        self.pdf.set_font('Arial', 'B', 12)
        self.pdf.cell(0, 10, 'Website Summary:', ln=True)
        
        # Headers for summary table
        self.pdf.set_font('Arial', 'B', 11)
        self.pdf.cell(80, 10, 'Website', 1, 0)
        self.pdf.cell(35, 10, 'URLs Analyzed', 1, 0, 'C')
        self.pdf.cell(35, 10, 'Average Score', 1, 0, 'C')
        self.pdf.cell(40, 10, 'Risk Level', 1, 1, 'C')
        
        # Add each website to the summary table
        self.pdf.set_font('Arial', '', 10)
        for domain, links in detected_links_by_origin.items():
            # Calculate average score for this domain
            if links:
                try:
                    avg_score = sum(float(link.get('phishing_score', 0)) for link in links) / len(links)
                    # Determine risk level based on average score
                    if avg_score >= 70:
                        risk_level = "High Risk"
                        self.pdf.set_text_color(255, 0, 0)  # Red
                    elif avg_score <= 30:
                        risk_level = "Low Risk"
                        self.pdf.set_text_color(0, 128, 0)  # Green
                    else:
                        risk_level = "Medium Risk"
                        self.pdf.set_text_color(0, 0, 0)  # Black
                    # Add row to summary table
                    self.pdf.cell(80, 10, domain, 1, 0)
                    self.pdf.cell(35, 10, str(len(links)), 1, 0, 'C')
                    self.pdf.cell(35, 10, f"{avg_score:.2f}%", 1, 0, 'C')
                    self.pdf.cell(40, 10, risk_level, 1, 1, 'C')
                    # Reset text color
                    self.pdf.set_text_color(0, 0, 0)
                except Exception as e:
                    print(f"Error processing domain {domain}: {e}")
                    # Continue with next domain
        
        # Add detailed analysis section for each website
        self.pdf.ln(10)
        self.pdf.set_font('Arial', 'B', 14)
        self.pdf.cell(0, 10, 'Detailed Analysis By Website', ln=True, align='C')
        
        # Process each website's results separately

        for domain, links in detected_links_by_origin.items():
            # Skip if no links found for this domain
            if not links:
                continue
            try:
                # Check if we need a new page
                if self.pdf.get_y() > 240:  # If we're too close to the bottom of the page
                    self.pdf.add_page()
                # Website header
                self.pdf.ln(5)
                self.pdf.set_font('Arial', 'B', 12)
                self.pdf.cell(0, 10, f'Website: {domain}', ln=True)
                # Calculate counts for this domain
                phishing_count = sum(1 for link in links if float(link.get('phishing_score', 0)) >= 70)
                medium_count = sum(1 for link in links if 30 < float(link.get('phishing_score', 0)) < 70)
                safe_count = sum(1 for link in links if float(link.get('phishing_score', 0)) <= 30)
                # Calculate average score
                total_score = sum(float(link.get('phishing_score', 0)) for link in links)
                average_score = total_score / len(links) if links else 0
                # Add table headers for this domain
                self.pdf.set_font('Arial', 'B', 11)
                self.pdf.cell(140, 10, 'URL', 1, 0)
                self.pdf.cell(50, 10, 'Phishing Score', 1, 1, 'C')
                # Add URLs for this domain
                self.pdf.set_font('Arial', '', 10)
                self.temp_processed_links = set()
                for link in links:
                    # Skip if this URL has already been processed
                    if link.get('url', 'Unknown URL') in self.temp_processed_links:
                        continue
                    # Calculate score color
                    score = float(link.get('phishing_score', 0))
                    if score >= 70:
                        self.pdf.set_text_color(255, 0, 0)  # Red
                    elif score <= 30:
                        self.pdf.set_text_color(0, 128, 0)  # Green
                    else:
                        self.pdf.set_text_color(0, 0, 0)    # Black
                    # Write URL (with word wrap if needed)
                    url_text = str(link.get('url', 'Unknown URL'))[:80]
                    self.pdf.cell(140, 10, url_text, 1, 0)
                    self.pdf.cell(50, 10, f"{score}%", 1, 1, 'C')
                    # Add to processed links to avoid duplicates
                    self.temp_processed_links.add(link.get('url', 'Unknown URL'))
                # Reset text color
                self.pdf.set_text_color(0, 0, 0)
                # Add domain summary - Check if we need a new page before summary
                if self.pdf.get_y() > 230:  # If less than ~60px left on page
                    self.pdf.add_page()
                self.pdf.ln(5)  # Ensure summary lines start at the left margin
                self.pdf.set_font('Arial', 'B', 11)
                self.pdf.cell(0, 10, f'Summary for {domain}:', ln=True)
                # Determine summary based on average score
                if average_score >= 70:
                    summary_text = "Detected as a phishing site."
                    self.pdf.set_text_color(255, 0, 0)  # Red
                elif average_score <= 30:
                    summary_text = "Not a phishing site."
                    self.pdf.set_text_color(0, 128, 0)  # Green
                else:
                    summary_text = "May be a phishing site (mixed results)."
                    self.pdf.set_text_color(0, 0, 0)  # Black
                self.pdf.set_font('Arial', '', 10)
                self.pdf.multi_cell(0, 10, summary_text)
                # Reset text color
                self.pdf.set_text_color(0, 0, 0)
                # Make sure all summary lines have enough vertical space
                # If close to bottom of page, add a new page
                if self.pdf.get_y() > 240:
                    self.pdf.add_page()
                self.pdf.ln()  # Add a line break before summary lines
                self.pdf.cell(0, 10, f"High Risk URLs: {phishing_count}", ln=True, align='L')
                self.pdf.cell(0, 10, f"Medium Risk URLs: {medium_count}", ln=True, align='L')
                self.pdf.cell(0, 10, f"Low Risk URLs: {safe_count}", ln=True, align='L')
                self.pdf.cell(0, 10, f"Average Phishing Score: {average_score:.2f}%", ln=True, align='L')
                # Add separator between websites
                self.pdf.line(10, self.pdf.get_y() + 5, 200, self.pdf.get_y() + 5)
                self.pdf.ln(10)
                # Check if we need a new page after this website's details
                if self.pdf.get_y() > 250 and domain != list(detected_links_by_origin.keys())[-1]:
                    self.pdf.add_page()
            except Exception as e:
                print(f"Error generating report for domain {domain}: {e}")
                # Continue with next domain
        
        # Add the risk chart at the end
        self.pdf.add_page()
        self.pdf.set_font('Arial', 'B', 14)
        self.pdf.cell(0, 10, 'Risk Level Distribution', ln=True, align='C')
        self.pdf.ln(5)
        
        try:
            chart_data = self.generate_risk_chart(detected_links_by_origin)
            # Use a unique temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmpfile:
                tmpfile.write(chart_data.getvalue())
                temp_chart_path = tmpfile.name

            # Add the chart to the PDF
            self.pdf.image(temp_chart_path, x=10, y=None, w=190)

            # Clean up the temporary file
            os.remove(temp_chart_path)

            # Add some space after the chart
            self.pdf.ln(10)
        except Exception as e:
            print(f"Error generating chart: {e}")
            self.pdf.cell(0, 10, 'Error generating risk distribution chart', ln=True)
        
        # Save the report
        filename = f'reports/phishing_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        try:
            self.pdf.output(filename)
            if receiver_email:
                send_email(filename, receiver_email)
            print(f"Your report has been generated at {filename}")
            return filename
        except Exception as e:
            print(f"Error saving report: {e}")
            return None
    
    def print_to_console(self, detected_links_by_origin):
        report = "Phishing Detection Report\n"
        report += "=" * 30 + "\n"
        
        for domain, links in detected_links_by_origin.items():
            report += f"\nWebsite: {domain}\n"
            report += "-" * 20 + "\n"
            
            for link in links:
                report += f"URL: {link.get('url', 'Unknown')}, Phishing Score: {link.get('phishing_score', 'N/A')}\n"
                
            # Calculate average score for this domain
            if links:
                try:
                    avg_score = sum(float(link.get('phishing_score', 0)) for link in links) / len(links)
                    report += f"Average Phishing Score: {avg_score:.2f}%\n"
                except:
                    report += "Could not calculate average score\n"
                
        return report