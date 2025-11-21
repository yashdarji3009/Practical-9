"""
Scraping Detection Engine (Blue Team)
Detects unusual scraping activity and reconnaissance attempts
"""

import re
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple
import json
import ipaddress

class ScrapingDetectionEngine:
    def __init__(self, threshold_requests: int = 100, time_window: int = 60, 
                 suspicious_user_agents: List[str] = None):
        """
        Initialize detection engine
        
        Args:
            threshold_requests: Number of requests to trigger alert
            time_window: Time window in seconds for rate limiting
            suspicious_user_agents: List of suspicious user agent strings
        """
        self.threshold_requests = threshold_requests
        self.time_window = time_window
        
        # Default suspicious user agents
        if suspicious_user_agents is None:
            self.suspicious_user_agents = [
                'curl', 'wget', 'python-requests', 'scrapy', 'httpx',
                'bot', 'crawler', 'spider', 'harvester', 'scraper',
                'masscan', 'nmap', 'nikto', 'sqlmap'
            ]
        else:
            self.suspicious_user_agents = suspicious_user_agents
        
        # Track requests per IP
        self.ip_requests: Dict[str, deque] = defaultdict(lambda: deque())
        self.ip_user_agents: Dict[str, Set[str]] = defaultdict(set)
        self.ip_endpoints: Dict[str, Set[str]] = defaultdict(set)
        
        # Track patterns
        self.suspicious_patterns: List[Dict] = []
        self.blocked_ips: Set[str] = set()
        
        # Track subdomain enumeration patterns
        self.subdomain_enum_patterns = [
            r'/\w{1,20}\.',  # Subdomain-like paths
            r'/\d+\.',       # Numeric subdomains
            r'/(www|mail|ftp|admin|test|dev|api|secure|portal)\w*',  # Common subdomain names
        ]
        
        # Track email harvesting patterns
        self.email_harvest_patterns = [
            r'/contact',
            r'/about',
            r'/team',
            r'/staff',
            r'/directory',
            r'/people',
            r'@\w+\.',
        ]
    
    def is_suspicious_user_agent(self, user_agent: str) -> bool:
        """
        Check if user agent is suspicious
        """
        if not user_agent:
            return True  # Missing user agent is suspicious
        
        user_agent_lower = user_agent.lower()
        return any(suspicious in user_agent_lower for suspicious in self.suspicious_user_agents)
    
    def check_rate_limiting(self, ip: str) -> bool:
        """
        Check if IP exceeds rate limit
        Returns True if suspicious, False otherwise
        """
        current_time = time.time()
        
        # Remove old requests outside time window
        requests_queue = self.ip_requests[ip]
        while requests_queue and current_time - requests_queue[0] > self.time_window:
            requests_queue.popleft()
        
        # Check threshold
        if len(requests_queue) >= self.threshold_requests:
            return True
        
        # Record new request
        requests_queue.append(current_time)
        return False
    
    def detect_subdomain_enumeration(self, endpoint: str, user_agent: str) -> bool:
        """
        Detect subdomain enumeration attempts
        """
        endpoint_lower = endpoint.lower()
        
        # Check for subdomain enumeration patterns
        for pattern in self.subdomain_enum_patterns:
            if re.search(pattern, endpoint_lower):
                return True
        
        # Check for rapid requests to different endpoints
        return False
    
    def detect_email_harvesting(self, endpoint: str, referer: str = None) -> bool:
        """
        Detect email harvesting attempts
        """
        endpoint_lower = endpoint.lower()
        referer_lower = (referer or '').lower()
        
        # Check for email harvesting patterns
        for pattern in self.email_harvest_patterns:
            if re.search(pattern, endpoint_lower) or re.search(pattern, referer_lower):
                return True
        
        # Check for rapid traversal of contact/about pages
        return False
    
    def analyze_request(self, ip: str, endpoint: str, user_agent: str = None, 
                       referer: str = None, method: str = 'GET') -> Dict:
        """
        Analyze a single request and return threat assessment
        
        Returns:
            Dictionary with threat level and details
        """
        threat_score = 0
        indicators = []
        
        # Check rate limiting
        if self.check_rate_limiting(ip):
            threat_score += 50
            indicators.append(f"Rate limit exceeded: {len(self.ip_requests[ip])} requests in {self.time_window}s")
        
        # Check suspicious user agent
        if self.is_suspicious_user_agent(user_agent or ''):
            threat_score += 30
            indicators.append(f"Suspicious user agent: {user_agent}")
        
        # Track user agents per IP
        self.ip_user_agents[ip].add(user_agent or 'None')
        if len(self.ip_user_agents[ip]) > 5:  # Multiple user agents from same IP
            threat_score += 20
            indicators.append(f"Multiple user agents detected: {len(self.ip_user_agents[ip])}")
        
        # Track endpoints per IP
        self.ip_endpoints[ip].add(endpoint)
        
        # Detect subdomain enumeration
        if self.detect_subdomain_enumeration(endpoint, user_agent or ''):
            threat_score += 25
            indicators.append("Subdomain enumeration pattern detected")
        
        # Detect email harvesting
        if self.detect_email_harvesting(endpoint, referer):
            threat_score += 25
            indicators.append("Email harvesting pattern detected")
        
        # Check for rapid endpoint traversal (scraping pattern)
        if len(self.ip_endpoints[ip]) > 50:  # Many different endpoints from same IP
            threat_score += 30
            indicators.append(f"Rapid endpoint traversal: {len(self.ip_endpoints[ip])} unique endpoints")
        
        # Check for missing headers (bot behavior)
        if not user_agent or not referer:
            threat_score += 10
            indicators.append("Missing standard headers")
        
        # Determine threat level
        if threat_score >= 80:
            threat_level = "CRITICAL"
        elif threat_score >= 50:
            threat_level = "HIGH"
        elif threat_score >= 30:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"
        
        return {
            'ip': ip,
            'endpoint': endpoint,
            'user_agent': user_agent,
            'threat_score': threat_score,
            'threat_level': threat_level,
            'indicators': indicators,
            'timestamp': datetime.now().isoformat()
        }
    
    def process_request(self, ip: str, endpoint: str, user_agent: str = None,
                       referer: str = None, method: str = 'GET') -> Dict:
        """
        Process a request and return analysis result
        """
        analysis = self.analyze_request(ip, endpoint, user_agent, referer, method)
        
        # Store suspicious patterns
        if analysis['threat_level'] in ['HIGH', 'CRITICAL']:
            self.suspicious_patterns.append(analysis)
            
            # Auto-block critical threats
            if analysis['threat_level'] == 'CRITICAL':
                self.blocked_ips.add(ip)
                print(f"[ALERT] IP {ip} has been blocked due to critical threat")
        
        return analysis
    
    def generate_report(self, time_period: int = 3600) -> Dict:
        """
        Generate a security report for the specified time period
        
        Args:
            time_period: Time period in seconds to analyze
        """
        cutoff_time = datetime.now() - timedelta(seconds=time_period)
        
        recent_patterns = [
            p for p in self.suspicious_patterns
            if datetime.fromisoformat(p['timestamp']) >= cutoff_time
        ]
        
        # Group by threat level
        by_threat_level = defaultdict(list)
        by_ip = defaultdict(list)
        
        for pattern in recent_patterns:
            by_threat_level[pattern['threat_level']].append(pattern)
            by_ip[pattern['ip']].append(pattern)
        
        # Top threats
        top_ips = sorted(by_ip.items(), key=lambda x: len(x[1]), reverse=True)[:10]
        
        report = {
            'time_period_seconds': time_period,
            'total_suspicious_activities': len(recent_patterns),
            'by_threat_level': {
                level: len(patterns) for level, patterns in by_threat_level.items()
            },
            'blocked_ips': list(self.blocked_ips),
            'top_threat_ips': [
                {
                    'ip': ip,
                    'incidents': len(patterns),
                    'avg_threat_score': sum(p['threat_score'] for p in patterns) / len(patterns),
                    'threat_levels': [p['threat_level'] for p in patterns]
                }
                for ip, patterns in top_ips
            ],
            'recent_alerts': recent_patterns[-20:]  # Last 20 alerts
        }
        
        return report
    
    def is_blocked(self, ip: str) -> bool:
        """
        Check if IP is blocked
        """
        return ip in self.blocked_ips
    
    def unblock_ip(self, ip: str):
        """
        Manually unblock an IP
        """
        self.blocked_ips.discard(ip)
        print(f"[INFO] IP {ip} has been unblocked")
    
    def save_report(self, filename: str = None, time_period: int = 3600):
        """
        Save report to file
        """
        if filename is None:
            filename = f"detection_report_{int(time.time())}.json"
        
        report = self.generate_report(time_period)
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[*] Report saved to: {filename}")
        return filename


def main():
    """
    Example usage of the detection engine
    """
    # Initialize detection engine
    engine = ScrapingDetectionEngine(
        threshold_requests=50,  # 50 requests per minute
        time_window=60
    )
    
    # Simulate some requests
    print("[*] Simulating request patterns...\n")
    
    # Normal request
    result1 = engine.process_request(
        ip="192.168.1.100",
        endpoint="/",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        referer="https://google.com"
    )
    print(f"Request 1: {result1['threat_level']} - {result1['threat_score']}")
    
    # Suspicious user agent
    result2 = engine.process_request(
        ip="192.168.1.101",
        endpoint="/contact",
        user_agent="python-requests/2.28.0",
        referer=""
    )
    print(f"Request 2: {result2['threat_level']} - {result2['threat_score']}")
    print(f"  Indicators: {', '.join(result2['indicators'])}")
    
    # Rapid requests (rate limiting)
    print("\n[*] Simulating rapid requests...")
    for i in range(60):
        result = engine.process_request(
            ip="192.168.1.102",
            endpoint=f"/page{i}",
            user_agent="scrapy/2.9.0",
            method="GET"
        )
    
    final_result = engine.process_request(
        ip="192.168.1.102",
        endpoint="/page60",
        user_agent="scrapy/2.9.0"
    )
    print(f"\nRapid Requests: {final_result['threat_level']} - {final_result['threat_score']}")
    print(f"  Indicators: {', '.join(final_result['indicators'])}")
    
    # Generate report
    print("\n[*] Generating security report...")
    report = engine.generate_report(time_period=3600)
    print(f"\nTotal suspicious activities: {report['total_suspicious_activities']}")
    print(f"By threat level: {report['by_threat_level']}")
    print(f"Blocked IPs: {report['blocked_ips']}")
    
    # Save report
    engine.save_report()


if __name__ == "__main__":
    main()
