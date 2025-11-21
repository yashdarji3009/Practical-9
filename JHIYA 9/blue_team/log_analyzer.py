"""
Log Analyzer (Blue Team)
Analyzes web server logs to detect scraping and reconnaissance activity
"""

import re
import json
import time
from collections import defaultdict, Counter
from datetime import datetime
from typing import List, Dict, Tuple
import ipaddress

class LogAnalyzer:
    def __init__(self):
        """
        Initialize log analyzer
        """
        # Common log patterns
        self.apache_log_pattern = re.compile(
            r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) .*'
        )
        
        self.nginx_log_pattern = re.compile(
            r'(?P<ip>\S+) - - \[(?P<time>.*?)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) .* "(?P<referer>.*?)" "(?P<user_agent>.*?)"'
        )
        
        # Suspicious patterns
        self.suspicious_paths = [
            r'/admin', r'/wp-admin', r'/wp-login', r'/phpmyadmin',
            r'/.git', r'/.env', r'/config', r'/backup',
            r'/\w{1,10}\.', r'/\d+\.',  # Subdomain enumeration
            r'/contact', r'/about', r'/team', r'/directory',  # Email harvesting
        ]
        
        self.suspicious_status_codes = [403, 404, 500]
        self.suspicious_user_agents = [
            'bot', 'crawler', 'spider', 'scraper', 'harvester',
            'python', 'curl', 'wget', 'scrapy', 'nmap', 'sqlmap'
        ]
    
    def parse_apache_log(self, log_line: str) -> Dict:
        """
        Parse Apache log format
        """
        match = self.apache_log_pattern.match(log_line)
        if match:
            return match.groupdict()
        return None
    
    def parse_nginx_log(self, log_line: str) -> Dict:
        """
        Parse Nginx log format
        """
        match = self.nginx_log_pattern.match(log_line)
        if match:
            return match.groupdict()
        return None
    
    def is_suspicious_path(self, path: str) -> bool:
        """
        Check if path matches suspicious patterns
        """
        path_lower = path.lower()
        return any(re.search(pattern, path_lower) for pattern in self.suspicious_paths)
    
    def is_suspicious_user_agent(self, user_agent: str) -> bool:
        """
        Check if user agent is suspicious
        """
        if not user_agent:
            return True
        user_agent_lower = user_agent.lower()
        return any(suspicious in user_agent_lower for suspicious in self.suspicious_user_agents)
    
    def analyze_log_file(self, log_file: str, log_format: str = 'nginx') -> Dict:
        """
        Analyze a log file and return statistics
        
        Args:
            log_file: Path to log file
            log_format: 'nginx' or 'apache'
        """
        ip_stats = defaultdict(lambda: {
            'count': 0,
            'paths': set(),
            'user_agents': set(),
            'status_codes': Counter(),
            'suspicious_activities': 0
        })
        
        suspicious_ips = defaultdict(list)
        
        print(f"[*] Analyzing log file: {log_file}")
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                line_count = 0
                for line in f:
                    line_count += 1
                    if not line.strip():
                        continue
                    
                    # Parse log line
                    if log_format == 'nginx':
                        parsed = self.parse_nginx_log(line)
                    else:
                        parsed = self.parse_apache_log(line)
                    
                    if not parsed:
                        continue
                    
                    ip = parsed.get('ip', '')
                    path = parsed.get('path', '')
                    user_agent = parsed.get('user_agent', '')
                    status = parsed.get('status', '')
                    
                    # Update statistics
                    stats = ip_stats[ip]
                    stats['count'] += 1
                    stats['paths'].add(path)
                    stats['user_agents'].add(user_agent)
                    stats['status_codes'][status] += 1
                    
                    # Check for suspicious activity
                    suspicious = False
                    reasons = []
                    
                    if self.is_suspicious_path(path):
                        suspicious = True
                        reasons.append(f"Suspicious path: {path}")
                    
                    if self.is_suspicious_user_agent(user_agent):
                        suspicious = True
                        reasons.append(f"Suspicious user agent: {user_agent}")
                    
                    if status in ['403', '404', '500'] and stats['count'] > 10:
                        suspicious = True
                        reasons.append(f"Multiple {status} errors")
                    
                    if suspicious:
                        stats['suspicious_activities'] += 1
                        suspicious_ips[ip].append({
                            'path': path,
                            'user_agent': user_agent,
                            'status': status,
                            'reasons': reasons
                        })
                    
                    if line_count % 10000 == 0:
                        print(f"  Processed {line_count} lines...")
            
            print(f"[*] Analysis complete. Processed {line_count} lines.\n")
            
            # Generate report
            report = {
                'total_ips': len(ip_stats),
                'suspicious_ips': len(suspicious_ips),
                'ip_statistics': {},
                'top_suspicious_ips': []
            }
            
            # Calculate threat scores
            for ip, stats in ip_stats.items():
                threat_score = 0
                
                # Request count
                if stats['count'] > 100:
                    threat_score += 20
                if stats['count'] > 500:
                    threat_score += 30
                
                # Unique paths (scraping pattern)
                if len(stats['paths']) > 50:
                    threat_score += 25
                
                # Multiple user agents
                if len(stats['user_agents']) > 3:
                    threat_score += 15
                
                # Suspicious activities
                threat_score += stats['suspicious_activities'] * 5
                
                # Error rate
                error_count = sum(count for code, count in stats['status_codes'].items() 
                                if code in ['403', '404', '500'])
                if error_count > stats['count'] * 0.5:
                    threat_score += 20
                
                report['ip_statistics'][ip] = {
                    'request_count': stats['count'],
                    'unique_paths': len(stats['paths']),
                    'unique_user_agents': len(stats['user_agents']),
                    'suspicious_activities': stats['suspicious_activities'],
                    'threat_score': threat_score,
                    'status_codes': dict(stats['status_codes'])
                }
            
            # Top suspicious IPs
            sorted_ips = sorted(
                report['ip_statistics'].items(),
                key=lambda x: x[1]['threat_score'],
                reverse=True
            )[:20]
            
            report['top_suspicious_ips'] = [
                {
                    'ip': ip,
                    **stats,
                    'incidents': suspicious_ips.get(ip, [])[:10]  # Top 10 incidents
                }
                for ip, stats in sorted_ips
            ]
            
            return report
        
        except FileNotFoundError:
            print(f"[-] Error: Log file not found: {log_file}")
            return None
        except Exception as e:
            print(f"[-] Error analyzing log file: {e}")
            return None
    
    def save_report(self, report: Dict, filename: str = None):
        """
        Save analysis report to file
        """
        if filename is None:
            filename = f"log_analysis_report_{int(time.time())}.json"
        
        # Convert sets to lists for JSON serialization
        report_copy = json.loads(json.dumps(report, default=str))
        
        with open(filename, 'w') as f:
            json.dump(report_copy, f, indent=2)
        
        print(f"[*] Report saved to: {filename}")
        return filename


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Log Analyzer (Blue Team)')
    parser.add_argument('-f', '--file', required=True, help='Path to log file')
    parser.add_argument('--format', choices=['nginx', 'apache'], default='nginx', 
                       help='Log file format')
    parser.add_argument('-o', '--output', help='Output report file')
    
    args = parser.parse_args()
    
    analyzer = LogAnalyzer()
    
    # Analyze log file
    report = analyzer.analyze_log_file(args.file, args.format)
    
    if report:
        # Print summary
        print(f"\n{'='*60}")
        print("LOG ANALYSIS SUMMARY")
        print(f"{'='*60}")
        print(f"Total unique IPs: {report['total_ips']}")
        print(f"Suspicious IPs: {report['suspicious_ips']}")
        
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
        output_file = args.output if args.output else None
        analyzer.save_report(report, output_file)


if __name__ == "__main__":
    import time
    main()
