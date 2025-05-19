# email_sender.py
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.mime.text import MIMEText
import os

def send_email(report_filename, receiver_email):
    # Access environment variables - Remove the trailing spaces after variable names
    sender_email = os.getenv('EMAIL_USER')  # Removed space after 'EMAIL_USER'
    password = os.getenv('EMAIL_PASS')  # Removed space after 'EMAIL_PASS'
    
    # For debugging - let's verify we're getting values
    if not sender_email or not password:
        print("Warning: Email credentials not found in environment variables")
        print(f"EMAIL_USER value: {sender_email}")
        # Don't print the actual password, just whether it exists
        print(f"EMAIL_PASS exists: {password is not None}")

    # Create the email
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = "Phishing Detection Report"

    # Email body
    body = "Please find attached the phishing detection report."
    msg.attach(MIMEText(body, 'plain'))

    # Attach the report as a PDF file
    with open(report_filename, "rb") as attachment:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename= {os.path.basename(report_filename)}")
        msg.attach(part)

    # Send the email
    try:
        # Remove the space after "smtp.gmail.com"
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()  # Secure the connection
            server.login(sender_email, password)
            server.send_message(msg)
        print(f"Email sent successfully to {receiver_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")
        


