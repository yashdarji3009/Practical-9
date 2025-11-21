# How to Run This Program - Step by Step Guide

## Prerequisites

- Python 3.7 or higher installed (You have Python 3.12.1 ✓)
- Internet connection
- Command line/terminal access

## Step 1: Install Dependencies

Open PowerShell or Command Prompt in the project directory and run:

```bash
pip install -r requirements.txt
```

**If you get permission errors, use:**
```bash
python -m pip install -r requirements.txt
```

This will install:
- `requests` - For web requests and API calls
- `dnspython` - For DNS queries
- `python-whois` - For WHOIS data
- `ipaddress` - For IP address handling (built-in, but listed for completeness)

**Verify installation:**
```bash
pip list | findstr "requests dnspython"
```

You should see `requests` and `dnspython` in the list.

---

## Step 2: Choose What to Run

### Option A: RED TEAM Tools (Reconnaissance/Attacker)

#### 1. Subdomain Enumeration

**Basic Command:**
```bash
python red_team/subdomain_enum.py -d example.com
```

**What it does:**
- Searches Certificate Transparency logs
- Performs DNS queries
- Brute-forces common subdomain names
- Outputs discovered subdomains

**Example:**
```bash
# Test on a well-known domain (you have permission)
python red_team/subdomain_enum.py -d github.com

# Save results to file
python red_team/subdomain_enum.py -d github.com -o github_subdomains.txt
```

**Output:**
- Prints discovered subdomains to console
- Saves to file: `subdomains_<domain>_<timestamp>.txt`

---

#### 2. Email Harvesting

**Basic Command:**
```bash
python red_team/email_harvest.py -d example.com
```

**What it does:**
- Crawls the website for email addresses
- Queries WHOIS data for emails
- Uses regex to find email patterns
- Only finds emails from the target domain

**Example:**
```bash
# Basic harvesting
python red_team/email_harvest.py -d example.com

# Deeper crawl (more thorough, takes longer)
python red_team/email_harvest.py -d example.com --max-depth 3

# Save results
python red_team/email_harvest.py -d example.com -o emails.txt
```

**Output:**
- Prints discovered emails to console
- Saves to file: `emails_<domain>_<timestamp>.txt`

---

### Option B: BLUE TEAM Tools (Defense/Detection)

#### 1. Detection Engine Demo

**Basic Command:**
```bash
python blue_team/detection_engine.py
```

**What it does:**
- Simulates various attack scenarios
- Shows how the detection system works
- Demonstrates threat scoring
- Generates a security report

**Example:**
```bash
python blue_team/detection_engine.py
```

**Output:**
- Shows threat detection in real-time
- Generates report: `detection_report_<timestamp>.json`

**No external dependencies needed** - This demo runs standalone!

---

#### 2. Log File Analysis

**Basic Command:**
```bash
python blue_team/log_analyzer.py -f <log_file> --format nginx
```

**What it does:**
- Analyzes web server access logs
- Identifies suspicious IP addresses
- Detects scraping patterns
- Generates threat scores

**Example:**
```bash
# For Nginx logs
python blue_team/log_analyzer.py -f C:\nginx\logs\access.log --format nginx

# For Apache logs
python blue_team/log_analyzer.py -f C:\apache\logs\access.log --format apache

# Save report
python blue_team/log_analyzer.py -f access.log --format nginx -o report.json
```

**Note:** You need an actual log file for this to work. If you don't have one, you can skip this for now.

**Output:**
- Prints top suspicious IPs to console
- Generates report: `log_analysis_report_<timestamp>.json`

---

### Option C: Unified Interface (main.py)

**All tools in one place:**

**Red Team:**
```bash
# Subdomain enumeration
python main.py red subdomain -d example.com

# Email harvesting
python main.py red email -d example.com
```

**Blue Team:**
```bash
# Detection demo
python main.py blue detection

# Log analysis
python main.py blue log -f access.log --format nginx
```

---

## Step 3: Quick Test (Recommended First Step)

**Try the Blue Team detection demo first** - it doesn't require internet and shows how the system works:

```bash
python blue_team/detection_engine.py
```

Or use the interactive example runner:

```bash
python run_example.py
```

---

## Step 4: Common Use Cases

### Use Case 1: Test Subdomain Enumeration
```bash
python red_team/subdomain_enum.py -d example.com -o results.txt
```

### Use Case 2: Test Email Harvesting
```bash
python red_team/email_harvest.py -d example.com --max-depth 2
```

### Use Case 3: Test Detection System
```bash
python blue_team/detection_engine.py
```

### Use Case 4: Analyze Web Server Logs
```bash
python blue_team/log_analyzer.py -f access.log --format nginx -o report.json
```

---

## Command Options Reference

### Subdomain Enumeration Options:
```
-d, --domain       Target domain (required)
-w, --wordlist     Custom wordlist file (optional)
-t, --threads      Number of threads (default: 50)
-o, --output       Output file path (optional)
```

### Email Harvesting Options:
```
-d, --domain       Target domain (required)
-u, --url          Starting URL (optional, default: https://domain)
--max-depth        Crawl depth (default: 2, max recommended: 5)
-t, --threads      Number of threads (default: 10)
-o, --output       Output file path (optional)
```

### Log Analyzer Options:
```
-f, --file         Log file path (required)
--format           Log format: nginx or apache (default: nginx)
-o, --output       Output report file (optional)
```

---

## Troubleshooting

### Problem: "ModuleNotFoundError: No module named 'requests'"
**Solution:** Install dependencies:
```bash
pip install -r requirements.txt
```

### Problem: "DNS resolution failed"
**Solution:** 
- Check your internet connection
- Some domains may not resolve. Try a different domain.

### Problem: "Rate limiting" or connection errors
**Solution:**
- Reduce thread count: `-t 10` instead of `-t 50`
- Add delays between requests (may need to modify code)

### Problem: "Permission denied" when installing
**Solution:**
```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Problem: Log analyzer can't find file
**Solution:**
- Use full path to log file
- On Windows: `C:\path\to\access.log`
- Make sure the file exists

---

## Example Workflow

1. **First, test the Blue Team detection:**
   ```bash
   python blue_team/detection_engine.py
   ```

2. **Then try Red Team subdomain enumeration:**
   ```bash
   python red_team/subdomain_enum.py -d github.com
   ```

3. **Try email harvesting:**
   ```bash
   python red_team/email_harvest.py -d github.com --max-depth 2
   ```

4. **If you have web server logs, analyze them:**
   ```bash
   python blue_team/log_analyzer.py -f access.log --format nginx
   ```

---

## Important Legal Notice

⚠️ **CRITICAL:** Only use Red Team tools on:
- Systems you own
- Systems you have explicit written permission to test
- Public domains for educational purposes (be respectful)

Unauthorized access is illegal. Use responsibly!

---

## Need Help?

- Check the full README.md for detailed documentation
- Run any script with `--help` flag:
  ```bash
  python red_team/subdomain_enum.py --help
  python blue_team/log_analyzer.py --help
  ```

