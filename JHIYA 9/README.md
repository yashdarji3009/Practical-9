# Web Reconnaissance & OSINT Automation with Defense Tools

A comprehensive security testing framework that includes both offensive (Red Team) reconnaissance tools and defensive (Blue Team) detection scripts for identifying and defending against web scraping activities.

## Project Structure

```
JHIYA 9/
├── red_team/              # Red Team (Attacker) Tools
│   ├── subdomain_enum.py  # Subdomain enumeration tool
│   ├── email_harvest.py   # Email harvesting tool
│   └── __init__.py
├── blue_team/             # Blue Team (Defender) Tools
│   ├── detection_engine.py # Real-time scraping detection
│   ├── log_analyzer.py    # Log file analysis tool
│   └── __init__.py
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## Features

### Red Team (Attacker) Tools

#### 1. Subdomain Enumeration (`red_team/subdomain_enum.py`)
- **Certificate Transparency Logs**: Passive enumeration via CT logs (crt.sh)
- **DNS Brute-forcing**: Active DNS queries for subdomain discovery
- **DNS Record Analysis**: Queries NS, MX, TXT, CNAME records
- **Multi-threaded**: Fast enumeration with configurable threading
- **Export Results**: Save discovered subdomains to file

**Usage:**
```bash
# Basic usage
python red_team/subdomain_enum.py -d example.com

# With custom wordlist
python red_team/subdomain_enum.py -d example.com -w wordlist.txt

# Custom output file
python red_team/subdomain_enum.py -d example.com -o results.txt

# Adjust threading
python red_team/subdomain_enum.py -d example.com -t 100
```

#### 2. Email Harvesting (`red_team/email_harvest.py`)
- **Website Scraping**: Crawls websites to extract email addresses
- **WHOIS Data Mining**: Extracts emails from WHOIS records
- **Pattern Recognition**: Uses regex to find email patterns
- **Configurable Depth**: Control web crawling depth
- **Domain Filtering**: Only harvests emails from target domain

**Usage:**
```bash
# Basic usage
python red_team/email_harvest.py -d example.com

# Custom starting URL
python red_team/email_harvest.py -d example.com -u https://example.com/contact

# Control crawl depth
python red_team/email_harvest.py -d example.com --max-depth 3

# Custom output
python red_team/email_harvest.py -d example.com -o emails.txt
```

### Blue Team (Defender) Tools

#### 1. Detection Engine (`blue_team/detection_engine.py`)
- **Real-time Monitoring**: Analyzes incoming requests in real-time
- **Rate Limiting Detection**: Identifies excessive request patterns
- **User Agent Analysis**: Detects suspicious user agents
- **Pattern Recognition**: Identifies subdomain enumeration and email harvesting attempts
- **Automatic Blocking**: Auto-blocks critical threats
- **Threat Scoring**: Assigns threat scores to suspicious activities
- **Security Reports**: Generates comprehensive security reports

**Usage:**
```python
from blue_team.detection_engine import ScrapingDetectionEngine

# Initialize detection engine
engine = ScrapingDetectionEngine(
    threshold_requests=100,  # Requests per time window
    time_window=60           # Time window in seconds
)

# Process a request
result = engine.process_request(
    ip="192.168.1.100",
    endpoint="/contact",
    user_agent="python-requests/2.28.0",
    referer="",
    method="GET"
)

print(f"Threat Level: {result['threat_level']}")
print(f"Threat Score: {result['threat_score']}")
print(f"Indicators: {result['indicators']}")

# Generate report
report = engine.generate_report(time_period=3600)
print(f"Suspicious activities: {report['total_suspicious_activities']}")
print(f"Blocked IPs: {report['blocked_ips']}")
```

#### 2. Log Analyzer (`blue_team/log_analyzer.py`)
- **Log File Analysis**: Analyzes web server log files (Nginx/Apache)
- **Pattern Detection**: Identifies scraping patterns in historical logs
- **IP Threat Scoring**: Assigns threat scores to IP addresses
- **Suspicious Activity Detection**: Flags suspicious paths, user agents, and patterns
- **Comprehensive Reports**: Generates detailed analysis reports

**Usage:**
```bash
# Analyze Nginx log file
python blue_team/log_analyzer.py -f /var/log/nginx/access.log --format nginx

# Analyze Apache log file
python blue_team/log_analyzer.py -f /var/log/apache2/access.log --format apache

# Custom output file
python blue_team/log_analyzer.py -f access.log -o report.json
```

## Installation

1. **Clone or download this repository**

2. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

## Requirements

- Python 3.7+
- Internet connection (for API queries and web scraping)
- DNS resolution capability
- For log analysis: Access to web server log files

## Red Team Usage Examples

### Example 1: Subdomain Enumeration
```bash
# Discover all subdomains for example.com
python red_team/subdomain_enum.py -d example.com -o subdomains.txt

# Use custom wordlist for more thorough enumeration
python red_team/subdomain_enum.py -d example.com -w custom_wordlist.txt -t 100
```

### Example 2: Email Harvesting
```bash
# Harvest emails from example.com
python red_team/email_harvest.py -d example.com

# Deep crawl with custom starting point
python red_team/email_harvest.py -d example.com -u https://example.com/about --max-depth 4
```

## Blue Team Usage Examples

### Example 1: Real-time Detection
```python
from blue_team.detection_engine import ScrapingDetectionEngine

# Initialize engine
engine = ScrapingDetectionEngine(threshold_requests=50, time_window=60)

# Simulate web requests (integrate with your web framework)
# In Flask/FastAPI/Django, call this in request middleware

@app.before_request
def check_request():
    result = engine.process_request(
        ip=request.remote_addr,
        endpoint=request.path,
        user_agent=request.headers.get('User-Agent'),
        referer=request.headers.get('Referer'),
        method=request.method
    )
    
    if result['threat_level'] == 'CRITICAL':
        return "Request blocked", 403
    
    return None
```

### Example 2: Log Analysis
```bash
# Analyze access logs for scraping patterns
python blue_team/log_analyzer.py -f access.log --format nginx -o security_report.json

# Review the generated report
cat security_report.json | python -m json.tool
```

## Detection Capabilities

The Blue Team tools can detect:

1. **Rate Limiting Violations**: Excessive requests from single IP
2. **Suspicious User Agents**: Known scraping tools and bots
3. **Subdomain Enumeration**: Patterns indicating reconnaissance
4. **Email Harvesting**: Rapid traversal of contact/about pages
5. **Missing Headers**: Bot-like behavior (missing user-agent, referer)
6. **Multiple User Agents**: Same IP using multiple user agents
7. **Rapid Endpoint Traversal**: Scraping patterns across multiple pages
8. **Error Rate Analysis**: High 404/403/500 error rates indicating enumeration

## Security Considerations

⚠️ **Important Legal and Ethical Warnings:**

1. **Authorization Required**: Only use Red Team tools on systems you own or have explicit written permission to test
2. **Rate Limiting**: Always implement rate limiting to avoid overwhelming target servers
3. **Respect robots.txt**: Check and respect robots.txt files
4. **Legal Compliance**: Ensure compliance with local laws and regulations (CFAA, GDPR, etc.)
5. **Educational Purpose**: These tools are for educational and authorized security testing only
6. **Responsible Disclosure**: Report vulnerabilities responsibly to affected parties

## Threat Levels

The detection engine uses a threat scoring system:

- **LOW (0-29)**: Normal activity, no action needed
- **MEDIUM (30-49)**: Suspicious activity, monitor closely
- **HIGH (50-79)**: Likely malicious, consider blocking
- **CRITICAL (80+)**: Definite threat, auto-blocked

## Output Files

- **Subdomain Enumeration**: `subdomains_<domain>_<timestamp>.txt`
- **Email Harvesting**: `emails_<domain>_<timestamp>.txt`
- **Detection Reports**: `detection_report_<timestamp>.json`
- **Log Analysis Reports**: `log_analysis_report_<timestamp>.json`

## Integration Examples

### Flask Integration
```python
from flask import Flask, request
from blue_team.detection_engine import ScrapingDetectionEngine

app = Flask(__name__)
engine = ScrapingDetectionEngine()

@app.before_request
def detect_scraping():
    result = engine.process_request(
        ip=request.remote_addr,
        endpoint=request.path,
        user_agent=request.headers.get('User-Agent'),
        referer=request.headers.get('Referer'),
        method=request.method
    )
    
    if engine.is_blocked(request.remote_addr):
        return "Access Denied", 403
    
    if result['threat_level'] in ['HIGH', 'CRITICAL']:
        app.logger.warning(f"Threat detected: {result}")
```

### FastAPI Integration
```python
from fastapi import FastAPI, Request, Response
from blue_team.detection_engine import ScrapingDetectionEngine

app = FastAPI()
engine = ScrapingDetectionEngine()

@app.middleware("http")
async def detect_scraping(request: Request, call_next):
    result = engine.process_request(
        ip=request.client.host,
        endpoint=request.url.path,
        user_agent=request.headers.get('user-agent'),
        referer=request.headers.get('referer'),
        method=request.method
    )
    
    if engine.is_blocked(request.client.host):
        return Response("Access Denied", status_code=403)
    
    response = await call_next(request)
    return response
```

## Troubleshooting

### Common Issues

1. **DNS Resolution Errors**: Ensure DNS is properly configured
2. **Rate Limiting**: Target servers may rate-limit requests; reduce thread count
3. **SSL/TLS Errors**: Some sites may have SSL certificate issues
4. **Permission Errors**: Ensure log file access permissions for Blue Team tools

### Debug Mode

Enable verbose logging by modifying the scripts to include:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Contributing

This is an educational project. Feel free to:
- Report issues
- Suggest improvements
- Add new features
- Improve documentation

## License

This project is for educational purposes only. Use responsibly and ethically.

## Disclaimer

The tools in this repository are for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. The authors are not responsible for any misuse of these tools.

## Author

Created for security research and educational purposes.

## Version

Version 1.0.0

---

**Remember**: Always obtain proper authorization before using Red Team tools. Use Blue Team tools to protect your own infrastructure.
