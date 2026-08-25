#!/usr/bin/env python3
"""
BlackScan v3.0 - Complete Network & Web Vulnerability Scanner
Usage: sudo python3 full_scan.py -t 82.98.171.83 -w https://82.98.171.83
"""

import socket
import ipaddress
import threading
import queue
import subprocess
import time
import sys
import os
from datetime import datetime
import json
import argparse
import re
import ssl
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import hashlib
import whois
import dns.resolver

# Colors
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class CompleteScanner:
    def __init__(self, target, web_url=None, threads=200, timeout=2, aggressive=False, deep_scan=False):
        self.target = target
        self.web_url = web_url or f"http://{target}"
        self.threads = threads
        self.timeout = timeout
        self.aggressive = aggressive
        self.deep_scan = deep_scan
        self.results = {
            'network': {'hosts': [], 'open_ports': {}, 'services': {}},
            'web': {
                'urls': [],
                'forms': [],
                'emails': [],
                'phones': [],
                'staff': [],
                'technologies': [],
                'vulnerabilities': [],
                'hidden_endpoints': [],
                'comments': [],
                'admin_panels': []
            },
            'osint': {
                'domains': [],
                'subdomains': [],
                'whois': None,
                'dns_records': {}
            }
        }
        self.start_time = datetime.now()
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.visited_urls = set()
        self.queue_crawl = queue.Queue()

    
    def ping_host(self, ip):
        try:
            if sys.platform == 'darwin':
                result = subprocess.run(['ping', '-c', '1', '-t', str(self.timeout), ip],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      timeout=self.timeout)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', str(self.timeout), ip],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      timeout=self.timeout)
            return result.returncode == 0
        except:
            return False

    
    def sweep_hosts(self):
        hosts = []
        try:
            network = ipaddress.ip_network(self.target, strict=False)
        except ValueError:
            if self.ping_host(self.target):
                return [self.target]
            return []
        
        ip_queue = queue.Queue()
        for ip in network.hosts():
            ip_queue.put(str(ip))
        
        results = []
        
        def worker():
            while not ip_queue.empty():
                ip = ip_queue.get()
                if self.ping_host(ip):
                    with self.lock:
                        results.append(ip)
                        print(f"{Colors.GREEN}[+] {ip} is alive{Colors.RESET}")
                ip_queue.task_done()
        
        threads = []
        for _ in range(min(self.threads, ip_queue.qsize() or 1)):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
        
        ip_queue.join()
        for t in threads:
            t.join()
        
        return results
    
    def scan_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_network(self):
        print(f"\n{Colors.BLUE}[*] NETWORK SCAN...{Colors.RESET}")
        hosts = self.sweep_hosts()
        if not hosts:
            print(f"{Colors.RED}[!] No hosts found{Colors.RESET}")
            return
        
        self.results['network']['hosts'] = hosts
        
        ports = [21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,6379,8080,8443,27017] if not self.aggressive else \
                list(range(1, 1025)) + [3306,3389,5432,6379,8080,8443,27017,27018,27019,9200,9300,11211]
        
        for host in hosts:
            print(f"\n{Colors.CYAN}[*] Scanning {host}{Colors.RESET}")
            open_ports = []
            port_queue = queue.Queue()
            for port in ports:
                port_queue.put(port)
            
            def worker():
                while not port_queue.empty():
                    port = port_queue.get()
                    if self.scan_port(host, port):
                        with self.lock:
                            open_ports.append(port)
                            print(f"    {Colors.GREEN}[+] Port {port} open{Colors.RESET}")
                    port_queue.task_done()
            
            threads = []
            for _ in range(min(self.threads, port_queue.qsize() or 1)):
                t = threading.Thread(target=worker)
                t.start()
                threads.append(t)
            
            port_queue.join()
            for t in threads:
                t.join()
            
            self.results['network']['open_ports'][host] = sorted(open_ports)

    # ==================== WEB PORT DETECTION ====================
    
    def detect_web_ports(self, host, open_ports):
        web_ports = []
        for port in open_ports:
            if port in [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]:
                web_ports.append(port)
            else:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((host, port))
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    sock.close()
                    if 'HTTP' in response:
                        web_ports.append(port)
                        print(f"    {Colors.CYAN}[+] Web port detected: {port}{Colors.RESET}")
                except:
                    pass
        return web_ports

    # ==================== WEB SCANNING ====================
    
    def get_urls(self, url):
        """Get all URLs from a page"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = urljoin(url, link['href'])
                if href not in self.visited_urls:
                    self.visited_urls.add(href)
                    self.queue_crawl.put(href)
                    if href not in self.results['web']['urls']:
                        self.results['web']['urls'].append(href)
            
            for script in soup.find_all('script', src=True):
                script_url = urljoin(url, script['src'])
                if script_url not in self.visited_urls:
                    self.visited_urls.add(script_url)
                    self.queue_crawl.put(script_url)
                    self.results['web']['urls'].append(script_url)
            
            for css in soup.find_all('link', rel='stylesheet', href=True):
                css_url = urljoin(url, css['href'])
                if css_url not in self.visited_urls:
                    self.visited_urls.add(css_url)
                    self.results['web']['urls'].append(css_url)
            
            for img in soup.find_all('img', src=True):
                img_url = urljoin(url, img['src'])
                self.results['web']['urls'].append(img_url)
            
            return response.text
        except:
            return ""

    def extract_emails(self, text):
        """Extract email addresses"""
        pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = set(re.findall(pattern, text))
        for email in emails:
            if email not in self.results['web']['emails']:
                self.results['web']['emails'].append(email)
                print(f"    {Colors.PURPLE}[+] Email found: {email}{Colors.RESET}")
        return emails
    
    def extract_phones(self, text):
        """Extract phone numbers"""
        patterns = [
            r'(\+33|0)[1-9](\d{2}){4}',
            r'(\+33|0)[1-9][0-9]{8}',
            r'0[1-9][0-9]{8}',
            r'\+33[1-9][0-9]{8}',
            r'[0-9]{2}[\.\-\s][0-9]{2}[\.\-\s][0-9]{2}[\.\-\s][0-9]{2}[\.\-\s][0-9]{2}'
        ]
        phones = set()
        for pattern in patterns:
            for match in re.findall(pattern, text):
                phones.add(match)
        for phone in phones:
            if phone not in self.results['web']['phones']:
                self.results['web']['phones'].append(phone)
                print(f"    {Colors.PURPLE}[+] Phone found: {phone}{Colors.RESET}")
        return phones
    
    def extract_staff(self, text, url):
        """Extract staff names"""
        name_patterns = [
            r'(?:Mme|M\.|Mrs|Mr|Dr)\.?\s*([A-Z][a-z]+)\s+([A-Z][a-z]+)',
            r'([A-Z][a-z]+)\s+([A-Z][a-z]+)\s*(?:-\s*)?(?:Directeur|Manager|CEO|CTO|Responsable)',
            r'<h[1-6]>([^<]*(?:Directeur|Manager|CEO|CTO|Responsable|Président)[^<]*)</h[1-6]>',
            r'([A-Z][a-z]+)\s+([A-Z][a-z]+)\s*-\s*(?:CEO|CTO|CFO|COO|Directeur|Manager)'
        ]
        
        staff = []
        for pattern in name_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    name = f"{match[0]} {match[1]}" if len(match) > 1 else match[0]
                else:
                    name = match
                if name not in staff:
                    staff.append(name)
                    print(f"    {Colors.PURPLE}[+] Staff found: {name}{Colors.RESET}")
        
        return staff
    
    def extract_forms(self, html, url):
        """Extract HTML forms"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            inputs = []
            for inp in form.find_all('input'):
                input_type = inp.get('type', 'text')
                input_name = inp.get('name', '')
                if input_name:
                    inputs.append({'name': input_name, 'type': input_type})
            
            form_data = {
                'url': urljoin(url, action),
                'method': method,
                'inputs': inputs
            }
            self.results['web']['forms'].append(form_data)
            print(f"    {Colors.CYAN}[+] Form found: {method} -> {action} ({len(inputs)} fields){Colors.RESET}")
    
    def extract_technologies(self, html, headers):
        """Detect technologies used"""
        techs = []
        
        server = headers.get('Server', '')
        if server:
            techs.append(f"Server: {server}")
        
        x_powered = headers.get('X-Powered-By', '')
        if x_powered:
            techs.append(f"X-Powered-By: {x_powered}")
        
        soup = BeautifulSoup(html, 'html.parser')
        generator = soup.find('meta', {'name': 'generator'})
        if generator:
            techs.append(f"Generator: {generator.get('content', '')}")
        
        if 'jquery' in html.lower():
            techs.append('jQuery')
        if 'bootstrap' in html.lower():
            techs.append('Bootstrap')
        if 'react' in html.lower():
            techs.append('React')
        if 'vue' in html.lower():
            techs.append('Vue.js')
        if 'angular' in html.lower():
            techs.append('Angular')
        if 'wp-content' in html.lower() or 'wordpress' in html.lower():
            techs.append('WordPress')
        
        for tech in techs:
            if tech not in self.results['web']['technologies']:
                self.results['web']['technologies'].append(tech)
                print(f"    {Colors.BLUE}[+] Technology: {tech}{Colors.RESET}")
        
        return techs
    
    def find_admin_panels(self, url):
        """Find admin panels"""
        admin_paths = [
            '/admin', '/administrator', '/wp-admin', '/login', '/cpanel',
            '/dashboard', '/admin/login', '/manager', '/administration',
            '/controlpanel', '/manage', '/adminpanel', '/cp', '/panel',
            '/admin.php', '/admin.html', '/admin.asp', '/admin.aspx',
            '/wp-login.php', '/phpmyadmin', '/mysql', '/db', '/database'
        ]
        
        found = []
        for path in admin_paths:
            test_url = urljoin(url, path)
            try:
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                if response.status_code == 200:
                    found.append(test_url)
                    print(f"    {Colors.RED}[!] Admin panel found: {test_url}{Colors.RESET}")
            except:
                pass
        
        self.results['web']['admin_panels'] = found
        return found
    
    def find_comments(self, html):
        """Extract HTML comments"""
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        for comment in comments:
            comment = comment.strip()[:200]
            if comment and comment not in self.results['web']['comments']:
                self.results['web']['comments'].append(comment)
                if any(keyword in comment.lower() for keyword in ['todo', 'fixme', 'bug', 'password', 'api', 'key']):
                    print(f"    {Colors.RED}[!] Interesting comment: {comment}{Colors.RESET}")
                else:
                    print(f"    {Colors.YELLOW}[i] Comment: {comment}{Colors.RESET}")
    
    def check_vulnerabilities(self, url, html):
        """Check for basic vulnerabilities"""
        vulns = []
        
        xss_payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>']
        for payload in xss_payloads:
            if payload in html:
                vulns.append(f"Possible XSS with payload: {payload[:30]}...")
        
        sql_errors = ['sql', 'mysql', 'sqlite', 'postgresql', 'ORA-', 'SQL syntax']
        for error in sql_errors:
            if error.lower() in html.lower():
                vulns.append(f"Possible SQL error: {error}")
        
        if 'password' in html.lower() and 'type="password"' in html.lower():
            vulns.append("Password field detected (possible brute force)")
        
        if 'phpinfo()' in html.lower():
            vulns.append("phpinfo() exposed")
        
        backup_patterns = ['.bak', '.backup', '.old', '.tmp', '.swp']
        for pattern in backup_patterns:
            if pattern in url.lower():
                vulns.append(f"Possible backup file: {url}")
        
        if vulns:
            for vuln in vulns:
                self.results['web']['vulnerabilities'].append({'url': url, 'vuln': vuln})
                print(f"    {Colors.RED}[!] Vulnerability: {vuln}{Colors.RESET}")
    
    def crawl(self, start_url, depth=3):
        """Crawl the website"""
        print(f"\n{Colors.BLUE}[*] WEBSITE CRAWLING...{Colors.RESET}")
        print(f"{Colors.BLUE}[*] URL: {start_url}{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Depth: {depth}{Colors.RESET}\n")
        
        self.queue_crawl.put(start_url)
        self.visited_urls.add(start_url)
        
        current_depth = 0
        while not self.queue_crawl.empty() and current_depth < depth:
            url = self.queue_crawl.get()
            print(f"{Colors.CYAN}[*] Crawling: {url}{Colors.RESET}")
            
            try:
                response = self.session.get(url, timeout=self.timeout, verify=False)
                html = response.text
                
                self.extract_emails(html)
                self.extract_phones(html)
                staff = self.extract_staff(html, url)
                for s in staff:
                    if s not in self.results['web']['staff']:
                        self.results['web']['staff'].append(s)
                
                self.extract_forms(html, url)
                self.extract_technologies(html, response.headers)
                self.find_comments(html)
                self.check_vulnerabilities(url, html)
                
                soup = BeautifulSoup(html, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = urljoin(url, link['href'])
                    if href not in self.visited_urls and '#' not in href:
                        self.visited_urls.add(href)
                        self.queue_crawl.put(href)
                        if href not in self.results['web']['urls']:
                            self.results['web']['urls'].append(href)
                
                self.find_admin_panels(url)
                
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Error on {url}: {e}{Colors.RESET}")
            
            current_depth += 1

    # ==================== OSINT ====================
    
    def osint_scan(self):
        """OSINT scan (WHOIS, DNS, etc.)"""
        print(f"\n{Colors.BLUE}[*] OSINT SCAN...{Colors.RESET}")
        
        domain = self.web_url.replace('http://', '').replace('https://', '').split('/')[0]
        
        try:
            print(f"{Colors.CYAN}[*] WHOIS for {domain}{Colors.RESET}")
            w = whois.whois(domain)
            whois_data = {
                'domain': domain,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'emails': w.emails,
                'phone': w.phone
            }
            self.results['osint']['whois'] = whois_data
            
            if w.emails:
                for email in w.emails:
                    if isinstance(email, str):
                        self.results['web']['emails'].append(email)
                        print(f"    {Colors.PURPLE}[+] WHOIS Email: {email}{Colors.RESET}")
            
            if w.phone:
                self.results['web']['phones'].append(str(w.phone))
                print(f"    {Colors.PURPLE}[+] WHOIS Phone: {w.phone}{Colors.RESET}")
                
        except Exception as e:
            print(f"{Colors.YELLOW}[!] WHOIS failed: {e}{Colors.RESET}")
        
        try:
            print(f"{Colors.CYAN}[*] DNS for {domain}{Colors.RESET}")
            dns_records = {}
            for record in ['A', 'MX', 'NS', 'TXT', 'CNAME']:
                try:
                    answers = dns.resolver.resolve(domain, record)
                    dns_records[record] = [str(r) for r in answers]
                except:
                    pass
            
            self.results['osint']['dns_records'] = dns_records
            for record, values in dns_records.items():
                print(f"    {Colors.GREEN}[+] {record}: {', '.join(values)}{Colors.RESET}")
                
        except Exception as e:
            print(f"{Colors.YELLOW}[!] DNS failed: {e}{Colors.RESET}")

    # ==================== COMPLETE SCAN ====================
    
    def scan_all(self):
        """Run all scans"""
        print(f"{Colors.BLUE}[*] Target: {self.target}{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Mode: {'AGGRESSIVE' if self.aggressive else 'NORMAL'}{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Deep scan: {'YES' if self.deep_scan else 'NO'}{Colors.RESET}\n")
        
        # 1. Network scan
        self.scan_network()
        
        # 2. Web port detection
        if self.results['network']['hosts']:
            for host in self.results['network']['hosts']:
                if host in self.results['network']['open_ports']:
                    web_ports = self.detect_web_ports(host, self.results['network']['open_ports'][host])
                    if web_ports:
                        port = web_ports[0]
                        proto = 'https' if port in [443, 8443] else 'http'
                        self.web_url = f"{proto}://{host}:{port}"
                        print(f"{Colors.GREEN}[+] Web URL detected: {self.web_url}{Colors.RESET}")
                        break
        
        # 3. Web scan
        if self.web_url:
            try:
                try:
                    response = self.session.get(self.web_url, timeout=self.timeout, verify=False)
                    if response.status_code:
                        print(f"{Colors.GREEN}[+] Web server responds on {self.web_url}{Colors.RESET}")
                        self.crawl(self.web_url, depth=3 if self.deep_scan else 2)
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] Cannot reach {self.web_url}: {e}{Colors.RESET}")
                    print(f"{Colors.YELLOW}[!] Web server not responding. Check URL or ports.{Colors.RESET}")
                
                self.osint_scan()
            except Exception as e:
                print(f"{Colors.RED}[!] Web error: {e}{Colors.RESET}")
        
        # 4. Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate complete report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_complet_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n{Colors.GREEN}[+] Complete report: {filename}{Colors.RESET}")
        
        print(f"\n{Colors.PURPLE}{'='*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}📊 COMPLETE SUMMARY{Colors.RESET}")
        print(f"{Colors.PURPLE}{'='*70}{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}🌐 NETWORK:{Colors.RESET}")
        print(f"  {Colors.WHITE}Hosts: {len(self.results['network']['hosts'])}{Colors.RESET}")
        print(f"  {Colors.WHITE}Open ports: {sum(len(p) for p in self.results['network']['open_ports'].values())}{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}🌍 WEB:{Colors.RESET}")
        print(f"  {Colors.WHITE}URLs: {len(self.results['web']['urls'])}{Colors.RESET}")
        print(f"  {Colors.WHITE}Forms: {len(self.results['web']['forms'])}{Colors.RESET}")
        print(f"  {Colors.WHITE}Emails: {len(self.results['web']['emails'])}{Colors.RESET}")
        print(f"  {Colors.WHITE}Phones: {len(self.results['web']['phones'])}{Colors.RESET}")
        print(f"  {Colors.WHITE}Staff: {len(self.results['web']['staff'])}{Colors.RESET}")
        print(f"  {Colors.WHITE}Admin panels: {len(self.results['web']['admin_panels'])}{Colors.RESET}")
        print(f"  {Colors.WHITE}Technologies: {len(self.results['web']['technologies'])}{Colors.RESET}")
        
        if self.results['web']['vulnerabilities']:
            print(f"\n{Colors.RED}⚠️ VULNERABILITIES:{Colors.RESET}")
            for vuln in self.results['web']['vulnerabilities']:
                print(f"  {Colors.RED}• {vuln['url']}: {vuln['vuln']}{Colors.RESET}")
        else:
            print(f"\n{Colors.GREEN}✅ No vulnerabilities detected{Colors.RESET}")
        
        if self.results['osint']['whois']:
            print(f"\n{Colors.CYAN}🔍 OSINT:{Colors.RESET}")
            whois = self.results['osint']['whois']
            if whois.get('emails'):
                print(f"  {Colors.WHITE}WHOIS Emails: {', '.join(whois['emails'])}{Colors.RESET}")
            if whois.get('phone'):
                print(f"  {Colors.WHITE}WHOIS Phone: {whois['phone']}{Colors.RESET}")
        
        print(f"\n{Colors.PURPLE}{'='*70}{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Scan completed in {datetime.now() - self.start_time}{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(description='Complete Network & Web Vulnerability Scanner')
    parser.add_argument('-t', '--target', required=True, help='Target IP or network (e.g., 192.168.1.0/24)')
    parser.add_argument('-w', '--web', help='Website URL (e.g., http://example.com)')
    parser.add_argument('--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=int, default=2, help='Timeout in seconds (default: 2)')
    parser.add_argument('-a', '--aggressive', action='store_true', help='Aggressive mode (more ports, deeper scan)')
    parser.add_argument('-d', '--deep-scan', action='store_true', help='Deep scan (3 levels of crawling)')
    
    args = parser.parse_args()
    
    scanner = CompleteScanner(args.target, args.web, args.threads, args.timeout, args.aggressive, args.deep_scan)
    
    try:
        scanner.scan_all()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()