"""
Main demonstration script for Web Reconnaissance & OSINT Tools
Shows usage examples for both Red Team and Blue Team tools
"""

import argparse
import sys
from red_team.subdomain_enum import SubdomainEnumerator
from red_team.email_harvest import EmailHarvester
from blue_team.detection_engine import ScrapingDetectionEngine
from blue_team.log_analyzer import LogAnalyzer


def red_team_subdomain(args):
    """Run subdomain enumeration"""
    print("="*60)
    print("RED TEAM: Subdomain Enumeration")
    print("="*60)
    
    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[-] Error loading wordlist: {e}")
            return
    
    enumerator = SubdomainEnumerator(
        target_domain=args.domain,
        wordlist=wordlist,
        threads=args.threads
    )
    
    results = enumerator.enumerate_all()
    enumerator.save_results(args.output)
    
    print("\n[SUMMARY]")
    print(f"Target Domain: {args.domain}")
    print(f"Subdomains Found: {len(results)}")
    if results:
        print("\nDiscovered Subdomains:")
        for subdomain in sorted(results)[:20]:  # Show first 20
            print(f"  - {subdomain}")
        if len(results) > 20:
            print(f"  ... and {len(results) - 20} more")


def red_team_email(args):
    """Run email harvesting"""
    print("="*60)
    print("RED TEAM: Email Harvesting")
    print("="*60)
    
    harvester = EmailHarvester(
        target_domain=args.domain,
        max_depth=args.max_depth,
        threads=args.threads
    )
    
    results = harvester.harvest_all(args.url)
    harvester.save_results(args.output)
    
    print("\n[SUMMARY]")
    print(f"Target Domain: {args.domain}")
    print(f"Emails Found: {len(results)}")
    if results:
        print("\nDiscovered Emails:")
        for email in sorted(results):
            print(f"  - {email}")


def blue_team_detection(args):
    """Demonstrate detection engine"""
    print("="*60)
    print("BLUE TEAM: Scraping Detection Engine Demo")
    print("="*60)
    
    engine = ScrapingDetectionEngine(
        threshold_requests=args.threshold,
        time_window=args.time_window
    )
    
    # Simulate some requests
    print("\n[*] Simulating request patterns...\n")
    
    # Normal request
    result1 = engine.process_request(
        ip="192.168.1.100",
        endpoint="/",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        referer="https://google.com"
    )
    print(f"Normal Request: {result1['threat_level']} - Score: {result1['threat_score']}")
    
    # Suspicious user agent
    result2 = engine.process_request(
        ip="192.168.1.101",
        endpoint="/contact",
        user_agent="python-requests/2.28.0",
        referer=""
    )
    print(f"Suspicious UA: {result2['threat_level']} - Score: {result2['threat_score']}")
    if result2['indicators']:
        print(f"  Indicators: {', '.join(result2['indicators'])}")
    
    # Rapid requests (rate limiting)
    print("\n[*] Simulating rapid requests...")
    for i in range(args.threshold):
        engine.process_request(
            ip="192.168.1.102",
            endpoint=f"/page{i}",
            user_agent="scrapy/2.9.0",
            method="GET"
        )
    
    final_result = engine.process_request(
        ip="192.168.1.102",
        endpoint="/page999",
        user_agent="scrapy/2.9.0"
    )
    print(f"\nRapid Requests: {final_result['threat_level']} - Score: {final_result['threat_score']}")
    if final_result['indicators']:
        print(f"  Indicators: {', '.join(final_result['indicators'])}")
    
    # Generate and display report
    print("\n[*] Generating security report...")
    report = engine.generate_report(time_period=3600)
    
    print(f"\n{'='*60}")
    print("SECURITY REPORT")
    print(f"{'='*60}")
    print(f"Total Suspicious Activities: {report['total_suspicious_activities']}")
    print(f"\nBy Threat Level:")
    for level, count in report['by_threat_level'].items():
        print(f"  {level}: {count}")
    
    if report['blocked_ips']:
        print(f"\nBlocked IPs: {', '.join(report['blocked_ips'])}")
    
    if report['top_threat_ips']:
        print(f"\nTop Threat IPs:")
        for i, ip_data in enumerate(report['top_threat_ips'][:5], 1):
            print(f"  {i}. {ip_data['ip']}: {ip_data['incidents']} incidents, "
                  f"avg score: {ip_data['avg_threat_score']:.1f}")
    
    # Save report
    if args.output:
        engine.save_report(args.output)
    else:
        engine.save_report()


def blue_team_log_analysis(args):
    """Analyze log files"""
    print("="*60)
    print("BLUE TEAM: Log Analysis")
    print("="*60)
    
    analyzer = LogAnalyzer()
    report = analyzer.analyze_log_file(args.file, args.format)
    
    if report:
        print(f"\n{'='*60}")
        print("LOG ANALYSIS SUMMARY")
        print(f"{'='*60}")
        print(f"Total Unique IPs: {report['total_ips']}")
        print(f"Suspicious IPs: {report['suspicious_ips']}")
        
        if report['top_suspicious_ips']:
            print(f"\n{'='*60}")
            print("TOP 10 SUSPICIOUS IPs")
            print(f"{'='*60}")
            for i, ip_data in enumerate(report['top_suspicious_ips'][:10], 1):
                print(f"\n{i}. IP: {ip_data['ip']}")
                print(f"   Threat Score: {ip_data['threat_score']}")
                print(f"   Requests: {ip_data['request_count']}")
                print(f"   Unique Paths: {ip_data['unique_paths']}")
                print(f"   Suspicious Activities: {ip_data['suspicious_activities']}")
        
        # Save report
        if args.output:
            analyzer.save_report(report, args.output)
        else:
            analyzer.save_report(report)


def main():
    parser = argparse.ArgumentParser(
        description='Web Reconnaissance & OSINT Tools - Main Interface',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Red Team: Subdomain enumeration
  python main.py red subdomain -d example.com
  
  # Red Team: Email harvesting
  python main.py red email -d example.com
  
  # Blue Team: Detection demo
  python main.py blue detection
  
  # Blue Team: Log analysis
  python main.py blue log -f access.log --format nginx
        """
    )
    
    subparsers = parser.add_subparsers(dest='team', help='Team: red or blue')
    
    # Red Team subcommands
    red_parser = subparsers.add_parser('red', help='Red Team (Attacker) tools')
    red_subparsers = red_parser.add_subparsers(dest='tool', help='Tool to use')
    
    # Subdomain enumeration
    subdomain_parser = red_subparsers.add_parser('subdomain', help='Subdomain enumeration')
    subdomain_parser.add_argument('-d', '--domain', required=True, help='Target domain')
    subdomain_parser.add_argument('-w', '--wordlist', help='Wordlist file')
    subdomain_parser.add_argument('-t', '--threads', type=int, default=50, help='Threads')
    subdomain_parser.add_argument('-o', '--output', help='Output file')
    
    # Email harvesting
    email_parser = red_subparsers.add_parser('email', help='Email harvesting')
    email_parser.add_argument('-d', '--domain', required=True, help='Target domain')
    email_parser.add_argument('-u', '--url', help='Starting URL')
    email_parser.add_argument('--max-depth', type=int, default=2, help='Max depth')
    email_parser.add_argument('-t', '--threads', type=int, default=10, help='Threads')
    email_parser.add_argument('-o', '--output', help='Output file')
    
    # Blue Team subcommands
    blue_parser = subparsers.add_parser('blue', help='Blue Team (Defender) tools')
    blue_subparsers = blue_parser.add_subparsers(dest='tool', help='Tool to use')
    
    # Detection engine
    detection_parser = blue_subparsers.add_parser('detection', help='Detection engine demo')
    detection_parser.add_argument('--threshold', type=int, default=50, help='Request threshold')
    detection_parser.add_argument('--time-window', type=int, default=60, help='Time window (seconds)')
    detection_parser.add_argument('-o', '--output', help='Output report file')
    
    # Log analysis
    log_parser = blue_subparsers.add_parser('log', help='Log file analysis')
    log_parser.add_argument('-f', '--file', required=True, help='Log file path')
    log_parser.add_argument('--format', choices=['nginx', 'apache'], default='nginx', 
                           help='Log format')
    log_parser.add_argument('-o', '--output', help='Output report file')
    
    args = parser.parse_args()
    
    if not args.team:
        parser.print_help()
        return
    
    try:
        if args.team == 'red':
            if args.tool == 'subdomain':
                red_team_subdomain(args)
            elif args.tool == 'email':
                red_team_email(args)
            else:
                red_parser.print_help()
        elif args.team == 'blue':
            if args.tool == 'detection':
                blue_team_detection(args)
            elif args.tool == 'log':
                blue_team_log_analysis(args)
            else:
                blue_parser.print_help()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
