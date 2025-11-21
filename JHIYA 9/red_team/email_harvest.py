"""
Email Harvesting Tool (Red Team)
Multiple techniques for discovering email addresses
"""

import requests
import re
import dns.resolver
from urllib.parse import urljoin, urlparse
from typing import Set, List
import time
import concurrent.futures
import threading

class EmailHarvester:
    def __init__(self, target_domain: str, max_depth: int = 2, threads: int = 10, 
                 max_urls: int = 50, delay: float = 0.1, timeout: int = 5):
        """
        Initialize email harvester
        
        Args:
            target_domain: Target domain to harvest emails from
            max_depth: Maximum depth for web crawling
            threads: Number of concurrent threads
            max_urls: Maximum number of URLs to crawl (default: 50)
            delay: Delay between requests in seconds (default: 0.1 for faster)
            timeout: Request timeout in seconds (default: 5)
        """
        self.target_domain = target_domain
        self.max_depth = max_depth
        self.threads = threads
        self.max_urls = max_urls
        self.delay = delay
        self.timeout = timeout
        self.found_emails: Set[str] = set()
        self.visited_urls: Set[str] = set()
        self.url_lock = threading.Lock()
        self.email_lock = threading.Lock()
        
        # Create session pool for threading
        self.sessions = [requests.Session() for _ in range(threads)]
        for session in self.sessions:
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            session.timeout = timeout
        
        # Email regex pattern
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        
        # Priority keywords for email-rich pages
        self.priority_keywords = ['contact', 'about', 'team', 'staff', 'people', 
                                  'directory', 'leadership', 'who', 'email']
    
    def extract_emails_from_text(self, text: str) -> Set[str]:
        """
        Extract email addresses from text content
        """
        emails = set()
        matches = self.email_pattern.findall(text)
        
        for email in matches:
            email = email.lower().strip()
            # Filter to only emails from target domain
            if self.target_domain in email:
                emails.add(email)
        
        return emails
    
    def get_url_priority(self, url: str) -> int:
        """Calculate priority for URL (higher = more likely to have emails)"""
        url_lower = url.lower()
        priority = 0
        for keyword in self.priority_keywords:
            if keyword in url_lower:
                priority += 10
        return priority
    
    def should_skip_url(self, url: str) -> bool:
        """Check if URL should be skipped (images, CSS, JS, etc.)"""
        skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
                          '.css', '.js', '.pdf', '.zip', '.tar', '.gz',
                          '.mp4', '.mp3', '.avi', '.mov', '.wmv']
        url_lower = url.lower()
        return any(url_lower.endswith(ext) for ext in skip_extensions)
    
    def scrape_webpage(self, url: str, session: requests.Session = None) -> tuple:
        """
        Scrape a webpage for emails and links
        
        Returns:
            (emails_set, links_list)
        """
        if session is None:
            session = self.sessions[0]
        
        try:
            response = session.get(url, timeout=self.timeout, allow_redirects=True, 
                                 stream=False)  # Don't stream for faster processing
            response.raise_for_status()
            
            # Only process HTML content
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' not in content_type:
                return set(), []
            
            # Extract emails from page content
            emails = self.extract_emails_from_text(response.text)
            
            # Extract links for further crawling (limit to first 100 links)
            links = set()
            url_pattern = re.compile(
                r'href=["\'](https?://[^"\']+|/[^"\']*)["\']',
                re.IGNORECASE
            )
            
            link_count = 0
            for match in url_pattern.finditer(response.text):
                if link_count >= 100:  # Limit links per page
                    break
                link = match.group(1)
                # Convert relative URLs to absolute
                link = urljoin(url, link)
                # Only include links from target domain and skip unwanted URLs
                parsed = urlparse(link)
                if (self.target_domain in parsed.netloc or not parsed.netloc) and \
                   not self.should_skip_url(link):
                    links.add(link)
                    link_count += 1
            
            return emails, list(links)
            
        except Exception as e:
            return set(), []
    
    def harvest_from_website(self, start_url: str = None) -> Set[str]:
        """
        Harvest emails by crawling website (optimized with parallel processing)
        """
        if start_url is None:
            start_url = f"https://{self.target_domain}"
        
        print(f"[*] Starting web scraping from: {start_url}")
        print(f"[*] Using {self.threads} threads, max {self.max_urls} URLs, delay {self.delay}s")
        
        # Use priority queue (list sorted by priority)
        urls_to_visit = [(self.get_url_priority(start_url), start_url, 0)]  # (priority, url, depth)
        urls_processed = 0
        session_index = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            
            while urls_to_visit or futures:
                # Submit new tasks up to thread limit
                while len(futures) < self.threads and urls_to_visit and urls_processed < self.max_urls:
                    urls_to_visit.sort(reverse=True)  # Sort by priority (highest first)
                    priority, url, depth = urls_to_visit.pop(0)
                    
                    if depth > self.max_depth:
                        continue
                    
                    if self.should_skip_url(url):
                        continue
                    
                    # Thread-safe check and add
                    with self.url_lock:
                        if url in self.visited_urls:
                            continue
                        self.visited_urls.add(url)
                    
                    urls_processed += 1
                    
                    # Use round-robin session assignment
                    session = self.sessions[session_index % len(self.sessions)]
                    session_index += 1
                    
                    # Submit task
                    future = executor.submit(self.scrape_webpage, url, session)
                    futures[future] = (url, depth)
                    
                    if urls_processed % 10 == 0:
                        with self.email_lock:
                            email_count = len(self.found_emails)
                        print(f"[*] Progress: {urls_processed}/{self.max_urls} URLs, "
                              f"{email_count} emails found so far...")
                
                # Process completed tasks
                done, not_done = concurrent.futures.wait(
                    futures.keys(), timeout=0.1, return_when=concurrent.futures.FIRST_COMPLETED
                )
                
                for future in done:
                    url, depth = futures.pop(future)
                    try:
                        emails, links = future.result()
                        
                        # Add found emails (thread-safe)
                        with self.email_lock:
                            for email in emails:
                                if email not in self.found_emails:
                                    self.found_emails.add(email)
                                    print(f"[+] Found email: {email}")
                        
                        # Add new links to visit (thread-safe)
                        if depth < self.max_depth and urls_processed < self.max_urls:
                            with self.url_lock:
                                for link in links:
                                    if link not in self.visited_urls and not self.should_skip_url(link):
                                        priority = self.get_url_priority(link)
                                        urls_to_visit.append((priority, link, depth + 1))
                    
                    except Exception as e:
                        pass  # Silently continue on errors
                
                # Small delay to prevent overwhelming server
                if self.delay > 0:
                    time.sleep(self.delay / self.threads)  # Distributed delay
        
        print(f"[*] Completed crawling {urls_processed} URLs")
        return self.found_emails
    
    def harvest_from_social_media(self) -> Set[str]:
        """
        Search for emails in social media profiles
        (This is a placeholder - actual implementation would use APIs)
        """
        print(f"[*] Searching social media for emails related to {self.target_domain}")
        # Note: This would require API keys and proper implementation
        # For demonstration, we'll skip this
        return set()
    
    def harvest_from_whois(self) -> Set[str]:
        """
        Extract emails from WHOIS data
        """
        print(f"[*] Querying WHOIS for {self.target_domain}")
        
        try:
            import whois
            
            w = whois.whois(self.target_domain)
            
            # Extract emails from whois data
            emails = []
            if w.email:
                if isinstance(w.email, list):
                    emails.extend(w.email)
                else:
                    emails.append(w.email)
            
            # Check other fields that might contain emails
            for field in ['admin_email', 'registrant_email', 'tech_email']:
                if hasattr(w, field) and getattr(w, field):
                    emails.append(getattr(w, field))
            
            for email in emails:
                if email and self.target_domain in str(email).lower():
                    self.found_emails.add(str(email).lower())
                    print(f"[+] Found email (WHOIS): {email}")
        
        except Exception as e:
            print(f"[-] Error querying WHOIS: {e}")
        
        return self.found_emails
    
    def harvest_from_github(self) -> Set[str]:
        """
        Search GitHub for emails in commits, issues, etc.
        """
        print(f"[*] Searching GitHub for emails related to {self.target_domain}")
        
        try:
            # Search GitHub API for commits, issues containing domain
            api_url = f"https://api.github.com/search/code"
            params = {
                'q': f'"{self.target_domain}"',
                'per_page': 10
            }
            
            response = self.sessions[0].get(api_url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('items', [])[:5]:  # Limit to 5 results
                    # This is simplified - real implementation would fetch file content
                    pass
        
        except Exception as e:
            print(f"[-] Error searching GitHub: {e}")
        
        return set()
    
    def harvest_from_google_dorking(self) -> Set[str]:
        """
        Use Google dorking to find emails
        """
        print(f"[*] Using Google dorking for {self.target_domain}")
        
        queries = [
            f'site:{self.target_domain} "@{self.target_domain}"',
            f'"{self.target_domain}" "@{self.target_domain}"',
            f'intext:"@{self.target_domain}" filetype:pdf'
        ]
        
        # Note: Google search requires proper implementation with API or scraping
        # This is a placeholder
        return set()
    
    def harvest_all(self, start_url: str = None) -> Set[str]:
        """
        Run all harvesting techniques
        """
        print(f"\n{'='*60}")
        print(f"Starting email harvesting for: {self.target_domain}")
        print(f"{'='*60}\n")
        
        # WHOIS (fast, passive)
        self.harvest_from_whois()
        time.sleep(1)
        
        # Website scraping (active, can be detected)
        if start_url is None:
            start_url = f"https://{self.target_domain}"
        
        self.harvest_from_website(start_url)
        
        print(f"\n{'='*60}")
        print(f"Harvesting complete! Found {len(self.found_emails)} unique emails")
        print(f"{'='*60}\n")
        
        return self.found_emails
    
    def save_results(self, filename: str = None):
        """
        Save results to file
        """
        if filename is None:
            filename = f"emails_{self.target_domain}_{int(time.time())}.txt"
        
        with open(filename, 'w') as f:
            for email in sorted(self.found_emails):
                f.write(f"{email}\n")
        
        print(f"[*] Results saved to: {filename}")
        return filename


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Email Harvesting Tool (Red Team)')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-u', '--url', help='Starting URL (default: https://domain)')
    parser.add_argument('--max-depth', type=int, default=2, help='Max crawl depth (default: 2)')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads (default: 20, higher = faster)')
    parser.add_argument('--max-urls', type=int, default=50, help='Max URLs to crawl (default: 50, increase for more thorough)')
    parser.add_argument('--delay', type=float, default=0.1, help='Delay between requests in seconds (default: 0.1, lower = faster)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('--fast', action='store_true', help='Fast mode: 30 threads, 30 URLs, 0.05s delay')
    
    args = parser.parse_args()
    
    # Apply fast mode settings
    if args.fast:
        args.threads = 30
        args.max_urls = 30
        args.delay = 0.05
        args.max_depth = 1
        print("[!] Fast mode enabled: Limited crawling for speed")
    
    # Create harvester
    harvester = EmailHarvester(
        target_domain=args.domain,
        max_depth=args.max_depth,
        threads=args.threads,
        max_urls=args.max_urls,
        delay=args.delay,
        timeout=args.timeout
    )
    
    # Run harvesting
    results = harvester.harvest_all(args.url)
    
    # Save results
    output_file = args.output if args.output else None
    harvester.save_results(output_file)
    
    # Print summary
    print("\n[SUMMARY]")
    print(f"Target Domain: {args.domain}")
    print(f"Emails Found: {len(results)}")
    print("\nDiscovered Emails:")
    for email in sorted(results):
        print(f"  - {email}")


if __name__ == "__main__":
    main()
