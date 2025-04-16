# Web Application Vulnerability Scanner

## Overview

This project is a Web Application Vulnerability Scanner that combines machine learning techniques with heuristic checks to identify potential security vulnerabilities in web applications. The tool crawls websites, analyzes responses, and detects common web vulnerabilities such as SQL injection, XSS, directory listings, and exposed configuration files.

## Features

- **Machine Learning Detection**: Uses a Logistic Regression model trained on TF-IDF features to identify potential vulnerabilities
- **Heuristic Checks**: Detects common issues like directory listings and exposed config files
- **Web Crawling**: Recursively crawls websites up to a specified depth
- **Robots.txt Compliance**: Respects website crawling policies
- **Retry Mechanism**: Handles temporary network issues with exponential backoff
- **GUI Interface**: User-friendly graphical interface with progress tracking
- **Visual Reporting**: Generates pie charts showing vulnerability severity distribution
- **Remediation Guidance**: Provides references and video tutorials for found vulnerabilities

## Technical Details

### Machine Learning Model
- **Algorithm**: Logistic Regression with class balancing
- **Feature Extraction**: TF-IDF vectorization of request/response text
- **Additional Features**: SQL keywords and XSS payload counts
- **Accuracy**: Reported during model training (see console output)

### Vulnerability Detection
- **SQL Injection**: Detects common SQL keywords in requests
- **XSS**: Identifies script tags and JavaScript URIs
- **Directory Listing**: Checks for "Index of /" in responses
- **Exposed Configs**: Looks for .env and web.config files

### Technical Stack
- Python 3.x
- Libraries:
  - requests (with retry mechanism)
  - BeautifulSoup (HTML parsing)
  - scikit-learn (machine learning)
  - matplotlib (visualization)
  - tkinter (GUI)
  - PIL (image handling)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/web-vulnerability-scanner.git
   cd web-vulnerability-scanner
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

   (If requirements.txt isn't provided, install these packages manually:)
   ```bash
   pip install requests beautifulsoup4 scikit-learn matplotlib pillow
   ```

3. Run the application:
   ```bash
   python new2.py
   ```

## Usage

1. Enter the target URL in the input field
2. Set crawling parameters:
   - Max Depth: How many levels deep to crawl (default: 2)
   - Max Pages: Maximum number of pages to scan (default: 100)
3. Click "Start Scan"
4. View results in the output panel, including:
   - Detected vulnerabilities with severity levels
   - Remediation advice
   - Video tutorial links
   - Visual severity distribution chart

## Screenshots

(Include actual screenshots of the application in action here)

## Project Structure

```
web-vulnerability-scanner/
├── new2.py             # Main application file (enhanced version)
├── s.py                # Alternative version
├── p.jpg               # Background image for GUI
├── README.md           # This file
└── requirements.txt    # Python dependencies
```

## Limitations

1. The current model is trained on a small synthetic dataset. For production use, it should be trained on real-world data.
2. Only basic vulnerability types are detected. More sophisticated attacks may be missed.
3. The crawler may not handle all website structures perfectly.
4. JavaScript-heavy sites may not be fully analyzed.

## Future Enhancements

- [ ] Expand training dataset with real-world examples
- [ ] Add more vulnerability types (CSRF, SSRF, etc.)
- [ ] Implement authenticated scanning
- [ ] Add command-line interface version
- [ ] Support for scanning REST APIs
- [ ] Export reports in multiple formats (PDF, HTML)

## Ethical Considerations

This tool should only be used on:
- Websites you own
- Websites where you have explicit permission to test
- Never use this tool for unauthorized security testing

Unauthorized scanning may be illegal in many jurisdictions.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any:
- Bug fixes
- New features
- Documentation improvements
- Dataset enhancements

## License

[MIT License](LICENSE)

## Acknowledgments

- OWASP for vulnerability references
- scikit-learn developers
- Python community for excellent libraries
