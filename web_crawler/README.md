# Phishing Detection System

A powerful tool designed to detect and analyze potential phishing websites by crawling and analyzing URLs for suspicious characteristics.

## Features

- URL analysis and phishing score calculation
- Multi-URL batch processing
- Detailed email reports
- Local report storage
- User-friendly command-line interface
- Comprehensive website documentation

## Prerequisites

- Python 3.7 or higher
- pip (Python package manager)
- Terminal or command-line interface
- Git (optional, for cloning the repository)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/ThiyaraBandara/PUSL3190-Final_Year_project.git
```

2. Navigate to the project directory:
```bash
cd web_crawler
```

3. (Optional) Create and activate a virtual environment:
```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Unix or MacOS:
source venv/bin/activate
```

4. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the main script:
```bash
python main.py
```

2. Enter URLs to analyze when prompted:
```
Enter the URL to analyze: http://example.com
Enter another URL (or type 'done' to finish): http://example2.com
Enter another URL (or type 'done' to finish): done
```

3. Provide an email address for the report:
```
Enter email address for the report: your.email@example.com
```

## Understanding Results

The system analyzes URLs and provides a phishing score based on various factors:

- **PHISHING** (Score 70+): High risk, likely a phishing site
- **MAYBE PHISHING** (Score 31-69): Medium risk, suspicious characteristics
- **NOT PHISHING** (Score 0-30): Low risk, appears legitimate

## Documentation

The project includes a comprehensive website with detailed documentation:

- [About](web_crawler/phishing-detection-website/main.html) - Overview of the system
- [How to Access](web_crawler/phishing-detection-website/github.html) - Repository access
- [How to Use](web_crawler/phishing-detection-website/usage.html) - Detailed usage instructions
- [Troubleshooting](web_crawler/phishing-detection-website/troubleshooting.html) - Common issues and solutions
- [Contact](web_crawler/phishing-detection-website/contact.html) - Support and inquiries

## Troubleshooting

Common issues and their solutions are documented in the troubleshooting guide. If you encounter any problems:

1. Check the [Troubleshooting](web_crawler/phishing-detection-website/troubleshooting.html) page
2. Ensure all dependencies are correctly installed
3. Verify your Python version meets the requirements
4. Contact support if issues persist

## Support

For support or inquiries, please contact:
- Email: k4253160@gmail.com

## License

© 2023 Phishing Detection System. All rights reserved.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 