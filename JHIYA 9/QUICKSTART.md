# Quick Start Guide

## Step 1: Install Dependencies

First, install all required Python packages:

```bash
pip install -r requirements.txt
```

If you encounter permission issues on Windows, use:

```bash
python -m pip install -r requirements.txt
```

## Step 2: Choose Your Tool

### RED TEAM TOOLS (Reconnaissance)

#### A. Subdomain Enumeration

**Basic Usage:**
```bash
python red_team/subdomain_enum.py -d example.com
```

**With custom options:**
```bash
# Use custom wordlist
python red_team/subdomain_enum.py -d example.com -w wordlist.txt

# Adjust thread count (more threads = faster but more aggressive)
python red_team/subdomain_enum.py -d example.com -t 100

# Save to specific file
python red_team/subdomain_enum.py -d example.com -o my_results.txt
```

**Example:**
```bash
python red_team/subdomain_enum.py -d google.com
```

#### B. Email Harvesting

**Basic Usage:**
```bash
python red_team/email_harvest.py -d example.com
```

**With custom options:**
```bash
# Custom starting URL
python red_team/email_harvest.py -d example.com -u https://example.com/contact

# Control crawl depth (1-5 recommended)
python red_team/email_harvest.py -d example.com --max-depth 3

# Save to specific file
python red_team/email_harvest.py -d example.com -o emails.txt
```

**Example:**
```bash
python red_team/email_harvest.py -d github.com --max-depth 2
```

### BLUE TEAM TOOLS (Defense)

#### A. Detection Engine (Real-time Demo)

**Run the demo:**
```bash
python blue_team/detection_engine.py
```

This will simulate various attack scenarios and show how the detection works.

#### B. Log File Analysis

**Basic Usage:**
```bash
python blue_team/log_analyzer.py -f path/to/access.log --format nginx
```

**For Apache logs:**
```bash
python blue_team/log_analyzer.py -f /var/log/apache2/access.log --format apache
```

**Save report:**
```bash
python blue_team/log_analyzer.py -f access.log --format nginx -o report.json
```

**Example with sample log (if you have one):**
```bash
python blue_team/log_analyzer.py -f access.log --format nginx
```

## Step 3: Using the Unified Interface (main.py)

The `main.py` file provides a unified command-line interface:

### Red Team Commands:

```bash
# Subdomain enumeration
python main.py red subdomain -d example.com

# Email harvesting
python main.py red email -d example.com
```

### Blue Team Commands:

```bash
# Detection engine demo
python main.py blue detection

# Log analysis
python main.py blue log -f access.log --format nginx
```

## Step 4: Integration Examples

### Using Detection Engine in Your Web Application

**Flask Example:**
```python
from flask import Flask, request
from blue_team.detection_engine import ScrapingDetectionEngine

app = Flask(__name__)
engine = ScrapingDetectionEngine(threshold_requests=50, time_window=60)

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
        print(f"ALERT: {result}")
```

## Troubleshooting

### Common Issues:

1. **ModuleNotFoundError**: Install dependencies with `pip install -r requirements.txt`

2. **DNS Resolution Errors**: Ensure you have internet connection and DNS configured properly

3. **Rate Limiting**: Some services may block rapid requests. Reduce thread count with `-t 10`

4. **Permission Errors**: On Windows, you may need to run PowerShell as Administrator

5. **SSL Errors**: Some sites may have certificate issues. This is normal for certain sites.

### Getting Help:

```bash
# See all options for subdomain enumeration
python red_team/subdomain_enum.py --help

# See all options for email harvesting
python red_team/email_harvest.py --help

# See all options for log analyzer
python blue_team/log_analyzer.py --help

# See unified interface help
python main.py --help
```

## Important Legal Notice

⚠️ **Only use Red Team tools on systems you own or have explicit written permission to test.**

Unauthorized access is illegal and unethical. Use these tools responsibly!

