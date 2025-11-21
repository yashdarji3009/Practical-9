"""
Subdomain Enumeration Tool (Red Team)
Multiple techniques for discovering subdomains
"""

import requests
import socket
import dns.resolver
import concurrent.futures
from urllib.parse import urlparse
import json
import time
from typing import List, Set

class SubdomainEnumerator:
    def __init__(self, target_domain: str, wordlist: List[str] = None, threads: int = 50):
        """
        Initialize subdomain enumerator
        
        Args:
            target_domain: Target domain to enumerate (e.g., example.com)
            wordlist: List of subdomain prefixes to try
            threads: Number of concurrent threads
        """
        self.target_domain = target_domain
        self.threads = threads
        self.found_subdomains: Set[str] = set()
        
        # Default wordlist if none provided
        if wordlist is None:
            self.wordlist = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'admin', 'forum', 'blog', 'news', 'shop', 'test', 'dev', 'api', 'secure',
                'vpn', 'ns', 'mail2', 'mx', 'cdn', 'm', 'portal', 'remote', 'db', 'www2',
                'api', 'ns2', 'www1', 'intranet', 'portal', 'online', 'ad', 'ads', 'pop3',
                'imap', 'mx1', 'sql', 'web', 'www3', 'sftp', 'apps', 'support', 'services',
                'dns', 'dns1', 'apps', 'wiki', 'mx2', 'smtp1', 'ftp2', 'exchange', 'ns3'
            ]
        else:
            self.wordlist = wordlist
    
    def dns_bruteforce(self) -> Set[str]:
        """
        Brute force subdomains using DNS queries
        """
        print(f"[*] Starting DNS brute-force enumeration for {self.target_domain}")
        
        def check_subdomain(subdomain: str) -> str:
            try:
                full_domain = f"{subdomain}.{self.target_domain}"
                socket.gethostbyname(full_domain)
                return full_domain
            except (socket.gaierror, socket.herror):
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in self.wordlist}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.found_subdomains.add(result)
                    print(f"[+] Found: {result}")
        
        return self.found_subdomains
    
    def certificate_transparency(self) -> Set[str]:
        """
        Query Certificate Transparency logs for subdomains
        """
        print(f"[*] Querying Certificate Transparency logs for {self.target_domain}")
        
        try:
            # Using crt.sh API
            url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    # Parse all names from certificate
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip()
                        if subdomain and self.target_domain in subdomain:
                            # Clean up wildcards and spaces
                            subdomain = subdomain.replace('*.', '')
                            if subdomain.startswith('.'):
                                subdomain = subdomain[1:]
                            if subdomain and subdomain not in ['', self.target_domain]:
                                self.found_subdomains.add(subdomain)
                                print(f"[+] Found (CT): {subdomain}")
        except Exception as e:
            print(f"[-] Error querying CT logs: {e}")
        
        return self.found_subdomains
    
    def dns_query(self) -> Set[str]:
        """
        Query DNS records for subdomains
        """
        print(f"[*] Querying DNS records for {self.target_domain}")
        
        try:
            # Query NS, MX, TXT records which might reveal subdomains
            record_types = ['NS', 'MX', 'TXT', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(self.target_domain, record_type)
                    for rdata in answers:
                        hostname = str(rdata.target if hasattr(rdata, 'target') else rdata)
                        # Extract potential subdomains
                        if self.target_domain in hostname:
                            self.found_subdomains.add(hostname.rstrip('.'))
                            print(f"[+] Found (DNS {record_type}): {hostname}")
                except Exception:
                    pass
        except Exception as e:
            print(f"[-] Error querying DNS: {e}")
        
        return self.found_subdomains
    
    def enumerate_all(self) -> Set[str]:
        """
        Run all enumeration techniques
        """
        print(f"\n{'='*60}")
        print(f"Starting subdomain enumeration for: {self.target_domain}")
        print(f"{'='*60}\n")
        
        # Certificate Transparency (fastest, passive)
        self.certificate_transparency()
        time.sleep(1)
        
        # DNS records
        self.dns_query()
        time.sleep(1)
        
        # DNS brute-force (most thorough but slower)
        self.dns_bruteforce()
        
        print(f"\n{'='*60}")
        print(f"Enumeration complete! Found {len(self.found_subdomains)} unique subdomains")
        print(f"{'='*60}\n")
        
        return self.found_subdomains
    
    def save_results(self, filename: str = None):
        """
        Save results to file
        """
        if filename is None:
            filename = f"subdomains_{self.target_domain}_{int(time.time())}.txt"
        
        with open(filename, 'w') as f:
            for subdomain in sorted(self.found_subdomains):
                f.write(f"{subdomain}\n")
        
        print(f"[*] Results saved to: {filename}")
        return filename


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Subdomain Enumeration Tool (Red Team)')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('-o', '--output', help='Output file path')
    
    args = parser.parse_args()
    
    # Load wordlist if provided
    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[-] Error loading wordlist: {e}")
            return
    
    # Create enumerator
    enumerator = SubdomainEnumerator(
        target_domain=args.domain,
        wordlist=wordlist,
        threads=args.threads
    )
    
    # Run enumeration
    results = enumerator.enumerate_all()
    
    # Save results
    output_file = args.output if args.output else None
    enumerator.save_results(output_file)
    
    # Print summary
    print("\n[SUMMARY]")
    print(f"Target Domain: {args.domain}")
    print(f"Subdomains Found: {len(results)}")
    print("\nDiscovered Subdomains:")
    for subdomain in sorted(results):
        print(f"  - {subdomain}")


if __name__ == "__main__":
    main()
