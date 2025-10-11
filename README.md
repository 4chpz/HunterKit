# HunterKit v1.0.0 - Professional Web Vulnerability Scanner

![HunterKit Logo](https://img.shields.io/badge/HunterKit-v1.0.0-red?style=for-the-badge&logo=security&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.7+-blue?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen?style=for-the-badge)

**The Most Advanced Web Vulnerability Scanner for Bug Bounty Hunters & Security Professionals**

*Professional-grade security scanner with enterprise-level detection capabilities*

**Developed by [Kawindu Wijewardhane](https://github.com/kawinduwijewardhane) | [@kawinduwijewardhane](https://twitter.com/k_wijewardhane)**

[Quick Start](#-quick-start) • [Documentation](#-documentation) • [Features](#-features) • [Usage](#-usage) • [Contributing](#-contributing)

---


## Overview

HunterKit is a **cutting-edge web vulnerability scanner** designed for security professionals, penetration testers, and bug bounty hunters. Built with advanced detection algorithms and comprehensive payload libraries, HunterKit delivers **enterprise-grade security assessment** capabilities with **zero false negatives**.

### Why HunterKit?

- ** Advanced Detection**: Context-aware vulnerability analysis with industry-leading accuracy
- ** Lightning Fast**: Multi-threaded scanning with intelligent rate limiting
- ** WAF Evasion**: Built-in techniques to bypass modern security protections
- ** Professional Reports**: Export-ready reports in TXT and JSON formats
- ** Highly Customizable**: Extensive payload libraries with easy customization
- ** Production Ready**: Battle-tested against real-world applications

---

## Features

### **Comprehensive Vulnerability Detection**

| Vulnerability Type | Payloads | Detection Method | Severity Levels |
|-------------------|----------|------------------|-----------------|
| **Cross-Site Scripting (XSS)** | 32 Advanced | Context-Aware Analysis | Low → Critical |
| **SQL Injection** | 33 Comprehensive | Error/Time/Boolean-Based | High → Critical |
| **Local File Inclusion (LFI)** | 29 Variants | Pattern Recognition | Medium → High |
| **Command Injection** | 40 Payloads | System Response Analysis | High → Critical |
| **Server-Side Template Injection** | 22 Engines | Template Expression Evaluation | High → Critical |

### **Advanced Security Features**

- ** WAF Detection & Evasion**: Identifies 10+ popular WAFs (Cloudflare, Akamai, AWS, etc.)
- ** Anti-Fingerprinting**: Header rotation and request obfuscation
- ** Smart Rate Limiting**: Intelligent delays to avoid detection
- ** Context Analysis**: Advanced XSS context evaluation
- ** Real-time Statistics**: Comprehensive scan metrics and performance data

---

##  Quick Start

###  Installation

```bash
# Download and extract HunterKit
cd HunterKit

# Install dependencies
pip3 install -r requirements.txt

# Make executable (Linux/macOS)
chmod +x hunterkit.py

# Run HunterKit
python3 hunterkit.py -u "https://target.com/search?q=test"
```

### Basic Usage

```bash
# Quick scan
python3 hunterkit.py -u "https://example.com/search?param=value"

# Advanced scan with custom settings
python3 hunterkit.py -u "https://target.com" -t 20 -d 0.5 --format json

# Debug mode for troubleshooting
python3 hunterkit.py -u "https://target.com" --debug
```

---

##  Usage Examples

###  **Command Line Options**

```bash
python3 hunterkit.py [OPTIONS]

Required Arguments:
  -u, --url URL          Target URL to scan (must include parameters)

Optional Arguments:
  -t, --threads INT      Number of concurrent threads (default: 10)
  -d, --delay FLOAT      Delay between requests in seconds (default: 1.0)
  --format FORMAT        Report format: txt or json (default: txt)
  --debug               Enable detailed debug output
  --no-banner           Suppress banner for automation
  -v, --version         Show version information
  -h, --help            Show help message
```

###  **Scan Examples**

```bash
# Basic vulnerability scan
python3 hunterkit.py -u "https://example.com/search.php?q=test"

# High-performance scan
python3 hunterkit.py -u "https://target.com" -t 30 -d 0.2

# Stealth scan
python3 hunterkit.py -u "https://target.com" -t 5 -d 2.0

# JSON report generation
python3 hunterkit.py -u "https://target.com" --format json

# Debug mode
python3 hunterkit.py -u "https://httpbin.org/get?test=value" --debug
```

---

##  Sample Output

```

  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ██╗  ██╗██╗████████╗  
  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██║ ██╔╝██║╚══██╔══╝  
  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝█████╔╝ ██║   ██║     
  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗██╔═██╗ ██║   ██║     
  ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║██║  ██╗██║   ██║     
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝     
                                                                            
            🎯 Professional Web Vulnerability Scanner                       
                   Advanced Bug Bounty Research Tool                        
                                                                                 
  🔍 XSS Detection     💉 SQL Injection        📁  LFI Testing        
  ⚡ SSTI Scanning     🔓 Command Injection    🛡️  WAF Detection      
  🎯 Custom Payloads   📊 Professional Reports ⚙️  Multi-threaded     
      

[INFO] Target: https://example.com/search?q=test
[SUCCESS] DNS resolution successful
[SUCCESS] Target is accessible (Status: 200)

 CROSS-SITE SCRIPTING (XSS) TESTING
────────────────────────────────────────────────────────────
[VULNERABILITY FOUND] XSS vulnerability detected!
  Type: Reflected XSS
  Severity: High
  Parameter: q
  Payload: <script>alert("XSS")</script>
  Context: HTML Document - Script Injection

 Final Scan Statistics:
   HTTP Requests Made: 156
   Security Payloads Tested: 142
   Vulnerabilities Discovered: 3
   Risk Level: HIGH
```

---

##  Payload Customization

###  **Payload Structure**
```
payloads/
├── xss_payloads.txt          # Cross-Site Scripting payloads
├── sql_payloads.txt          # SQL injection payloads
├── lfi_payloads.txt          # Local file inclusion payloads
├── ssti_payloads.txt         # Server-side template injection
└── command_payloads.txt      # Command injection payloads
```

###  **Adding Custom Payloads**
```bash
# Edit XSS payloads
echo '<svg onload=alert("custom")>' >> payloads/xss_payloads.txt

# Add SQL injection payload
echo "' AND (SELECT 1 FROM dual)='1'--" >> payloads/sql_payloads.txt
```

---

##  Security Features

###  **WAF Detection**
HunterKit automatically detects and adapts to popular Web Application Firewalls:

- **Cloudflare** - Header Analysis + Header Rotation
- **Akamai** - Response Patterns + Request Obfuscation  
- **AWS WAF** - Error Messages + Payload Encoding
- **Azure WAF** - Status Codes + User-Agent Rotation
- **Incapsula** - Cookie Analysis + Rate Limit Adaptation

###  **Anti-Detection Features**
- Header rotation with realistic User-Agent strings
- Intelligent delays with random jitter
- Automatic payload encoding for evasion
- Persistent session management

---

##  Requirements

###  **System Requirements**
- **Python**: 3.7 or higher
- **Operating System**: Linux, macOS, Windows
- **Memory**: Minimum 512MB RAM
- **Network**: Internet connection for target scanning

###  **Dependencies**
```
requests>=2.31.0
beautifulsoup4>=4.12.2
urllib3>=1.26.18
colorama>=0.4.6
```

---

##  Contributing

We welcome contributions from the security community!

###  **Ways to Contribute**
-  **Bug Reports**: Found an issue? Create a detailed issue report
-  **Feature Requests**: Have ideas? Share your suggestions
-  **Payload Contributions**: Add new XSS, SQL, LFI, SSTI, or command injection payloads
-  **Documentation**: Improve guides, add examples, fix typos

###  **Development Setup**
```bash
# Fork and clone the repository
git clone https://github.com/kawinduwijewardhane/HunterKit.git
cd HunterKit

# Install development dependencies
pip3 install -r requirements.txt

```

---

##  Community

###  **Join Our Community**
- ** Twitter**: [@k_wijewardhane](https://twitter.com/k_wijewardhane)
- ** LinkedIn**: [kawinduwijewardhane](https://linkedin.com/in/kawinduwijewardhane)
- ** Email**: security@kawindu.co.uk
- ** Website**: [kawindu.co.uk](https://www.kawindu.co.uk)

###  **Stay Updated**
-  **Star this repository** for updates
-  **Watch** for new releases
-  **Fork** to contribute
-  **Follow** [@k_wijewardhane](https://twitter.com/k_wijewardhane)

---

##  Legal Disclaimer

###  **Responsible Use**
HunterKit is designed **exclusively for authorized security testing**. Users must ensure:

-  **Explicit Permission**: Only test applications you own or have written authorization to test
-  **Legal Compliance**: Follow all applicable laws and regulations
-  **Responsible Disclosure**: Report vulnerabilities through proper channels
-  **Ethical Guidelines**: Adhere to responsible security research practices

###  **Legal Notice**
- **Unauthorized testing** may violate laws including the Computer Fraud and Abuse Act (CFAA)
- **Users are solely responsible** for ensuring authorized use
- **The developer assumes no liability** for misuse of this tool
- **Commercial use** requires proper licensing and authorization

---

##  License

```
MIT License

Copyright (c) 2025 Kawindu Wijewardhane

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

---

##  **Thank You for Using HunterKit!** 

**If HunterKit helped you in your security research, please consider:**

 **Starring this repository**  
 **Following [@k_wijewardhane](https://twitter.com/k_wijewardhane)**  
 **Contributing to the project**  
 **Sharing with the community**

---

###  **Happy Ethical Hacking!** 

**Built with ❤️ by the security community, for the security community**

**[Kawindu Wijewardhane](https://github.com/kawinduwijewardhane) | [@kawinduwijewardhane](https://twitter.com/k_wijewardhane) | [kawindu.co.uk](https://www.kawindu.co.uk)**

---

