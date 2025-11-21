"""
Simple example script to demonstrate how to run the tools
This script shows basic usage examples
"""

def main():
    print("="*70)
    print("WEB RECONNAISSANCE & OSINT TOOLS - EXAMPLE RUNNER")
    print("="*70)
    print()
    
    print("Before running, make sure to install dependencies:")
    print("  pip install -r requirements.txt")
    print()
    
    print("="*70)
    print("RED TEAM EXAMPLES (Attacker/Reconnaissance)")
    print("="*70)
    print()
    
    print("1. SUBDOMAIN ENUMERATION:")
    print("   python red_team/subdomain_enum.py -d example.com")
    print("   python red_team/subdomain_enum.py -d example.com -o results.txt")
    print("   python red_team/subdomain_enum.py -d example.com -t 50")
    print()
    
    print("2. EMAIL HARVESTING:")
    print("   python red_team/email_harvest.py -d example.com")
    print("   python red_team/email_harvest.py -d example.com --max-depth 3")
    print("   python red_team/email_harvest.py -d example.com -o emails.txt")
    print()
    
    print("="*70)
    print("BLUE TEAM EXAMPLES (Defender/Detection)")
    print("="*70)
    print()
    
    print("3. DETECTION ENGINE DEMO:")
    print("   python blue_team/detection_engine.py")
    print()
    
    print("4. LOG FILE ANALYSIS:")
    print("   python blue_team/log_analyzer.py -f access.log --format nginx")
    print("   python blue_team/log_analyzer.py -f access.log --format apache -o report.json")
    print()
    
    print("="*70)
    print("UNIFIED INTERFACE (using main.py)")
    print("="*70)
    print()
    
    print("Red Team:")
    print("   python main.py red subdomain -d example.com")
    print("   python main.py red email -d example.com")
    print()
    
    print("Blue Team:")
    print("   python main.py blue detection")
    print("   python main.py blue log -f access.log --format nginx")
    print()
    
    print("="*70)
    print("QUICK DEMO - Try This Now:")
    print("="*70)
    print()
    print("To test the Blue Team detection engine:")
    print("   python blue_team/detection_engine.py")
    print()
    print("This will simulate various attack scenarios and show how")
    print("the detection system identifies suspicious activity.")
    print()
    
    # Ask user if they want to run a demo
    try:
        response = input("Would you like to run the Blue Team detection demo now? (y/n): ")
        if response.lower() == 'y':
            print("\nRunning Blue Team Detection Demo...\n")
            from blue_team.detection_engine import ScrapingDetectionEngine
            
            engine = ScrapingDetectionEngine(threshold_requests=50, time_window=60)
            
            print("[*] Simulating request patterns...\n")
            
            # Normal request
            result1 = engine.process_request(
                ip="192.168.1.100",
                endpoint="/",
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                referer="https://google.com"
            )
            print(f"✓ Normal Request: {result1['threat_level']} - Score: {result1['threat_score']}")
            
            # Suspicious user agent
            result2 = engine.process_request(
                ip="192.168.1.101",
                endpoint="/contact",
                user_agent="python-requests/2.28.0",
                referer=""
            )
            print(f"✓ Suspicious User Agent: {result2['threat_level']} - Score: {result2['threat_score']}")
            if result2['indicators']:
                print(f"  → {', '.join(result2['indicators'])}")
            
            print("\n[*] Simulating rapid requests...")
            # Rapid requests
            for i in range(55):
                engine.process_request(
                    ip="192.168.1.102",
                    endpoint=f"/page{i}",
                    user_agent="scrapy/2.9.0"
                )
            
            final_result = engine.process_request(
                ip="192.168.1.102",
                endpoint="/page999",
                user_agent="scrapy/2.9.0"
            )
            print(f"✓ Rapid Requests: {final_result['threat_level']} - Score: {final_result['threat_score']}")
            if final_result['indicators']:
                print(f"  → {', '.join(final_result['indicators'])}")
            
            # Generate report
            print("\n[*] Generating security report...")
            report = engine.generate_report(time_period=3600)
            
            print(f"\n{'='*60}")
            print("SECURITY REPORT SUMMARY")
            print(f"{'='*60}")
            print(f"Total Suspicious Activities: {report['total_suspicious_activities']}")
            print(f"\nThreat Level Breakdown:")
            for level, count in report['by_threat_level'].items():
                print(f"  {level}: {count}")
            
            if report['blocked_ips']:
                print(f"\n⚠️  Blocked IPs: {', '.join(report['blocked_ips'])}")
            
            print("\n✓ Demo completed successfully!")
            print("\nTo use Red Team tools or analyze logs, see the examples above.")
    except KeyboardInterrupt:
        print("\n\nDemo cancelled by user.")
    except Exception as e:
        print(f"\nError running demo: {e}")
        print("Make sure dependencies are installed: pip install -r requirements.txt")


if __name__ == "__main__":
    main()

