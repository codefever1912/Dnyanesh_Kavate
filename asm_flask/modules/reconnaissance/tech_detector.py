#!/usr/bin/env python3
"""
Technology Stack Detection Module for Attack Surface Monitoring Tool
This module identifies technologies used by web applications.
"""

import requests
import re
import json
import sys
from typing import Dict, Any, List, Optional, Set
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class TechnologyDetector:
    """
    A class to detect technologies used by web applications.
    """

    def __init__(self, target: str, timeout: int = 10):
        """
        Initialize the TechnologyDetector with the target URL.

        Args:
            target (str): The target URL to analyze.
            timeout (int): Timeout in seconds for HTTP requests.
        """
        self.target = target
        self.timeout = timeout
        self.technologies: Set[str] = set()
        self.headers: Dict[str, str] = {}
        self.html_content: str = ""
        self.cookies: Dict[str, str] = {}
        self.scripts: List[str] = []
        self.meta_tags: List[Dict[str, str]] = []
        
        # Technology signatures
        self.signatures = {
            # Web servers
            'apache': [
                {'type': 'header', 'pattern': r'apache', 'header': 'server'},
                {'type': 'header', 'pattern': r'x-powered-by:\s*php', 'header': 'x-powered-by'},
            ],
            'nginx': [
                {'type': 'header', 'pattern': r'nginx', 'header': 'server'},
            ],
            'iis': [
                {'type': 'header', 'pattern': r'microsoft-iis', 'header': 'server'},
                {'type': 'header', 'pattern': r'asp.net', 'header': 'x-powered-by'},
            ],
            'cloudflare': [
                {'type': 'header', 'pattern': r'cloudflare', 'header': 'server'},
                {'type': 'header', 'pattern': r'__cfduid', 'header': 'set-cookie'},
                {'type': 'cookie', 'pattern': r'__cfduid'},
            ],
            
            # Programming languages
            'php': [
                {'type': 'header', 'pattern': r'php', 'header': 'x-powered-by'},
                {'type': 'cookie', 'pattern': r'phpsessid'},
            ],
            'asp.net': [
                {'type': 'header', 'pattern': r'asp.net', 'header': 'x-powered-by'},
                {'type': 'header', 'pattern': r'asp.net', 'header': 'x-aspnet-version'},
                {'type': 'cookie', 'pattern': r'asp.net_sessionid'},
            ],
            'java': [
                {'type': 'header', 'pattern': r'java', 'header': 'x-powered-by'},
                {'type': 'cookie', 'pattern': r'jsessionid'},
            ],
            'python': [
                {'type': 'header', 'pattern': r'python', 'header': 'x-powered-by'},
                {'type': 'header', 'pattern': r'wsgi', 'header': 'server'},
                {'type': 'header', 'pattern': r'django', 'header': 'server'},
                {'type': 'header', 'pattern': r'flask', 'header': 'server'},
            ],
            'ruby': [
                {'type': 'header', 'pattern': r'phusion', 'header': 'server'},
                {'type': 'header', 'pattern': r'rails', 'header': 'x-powered-by'},
                {'type': 'cookie', 'pattern': r'_session_id'},
            ],
            
            # CMS
            'wordpress': [
                {'type': 'html', 'pattern': r'wp-content'},
                {'type': 'html', 'pattern': r'wp-includes'},
                {'type': 'meta', 'name': 'generator', 'pattern': r'wordpress'},
                {'type': 'cookie', 'pattern': r'wordpress_'},
            ],
            'drupal': [
                {'type': 'html', 'pattern': r'drupal.js'},
                {'type': 'html', 'pattern': r'drupal.min.js'},
                {'type': 'meta', 'name': 'generator', 'pattern': r'drupal'},
                {'type': 'cookie', 'pattern': r'drupal'},
            ],
            'joomla': [
                {'type': 'html', 'pattern': r'/media/jui/'},
                {'type': 'html', 'pattern': r'/media/system/js/'},
                {'type': 'meta', 'name': 'generator', 'pattern': r'joomla'},
                {'type': 'cookie', 'pattern': r'joomla'},
            ],
            'magento': [
                {'type': 'html', 'pattern': r'magento'},
                {'type': 'cookie', 'pattern': r'frontend='},
            ],
            
            # JavaScript frameworks
            'jquery': [
                {'type': 'script', 'pattern': r'jquery'},
            ],
            'react': [
                {'type': 'html', 'pattern': r'react'},
                {'type': 'html', 'pattern': r'reactjs'},
                {'type': 'script', 'pattern': r'react'},
            ],
            'angular': [
                {'type': 'html', 'pattern': r'ng-app'},
                {'type': 'html', 'pattern': r'ng-controller'},
                {'type': 'html', 'pattern': r'angular'},
                {'type': 'script', 'pattern': r'angular'},
            ],
            'vue': [
                {'type': 'html', 'pattern': r'vue.js'},
                {'type': 'html', 'pattern': r'v-app'},
                {'type': 'html', 'pattern': r'v-bind'},
                {'type': 'script', 'pattern': r'vue'},
            ],
            
            # Analytics and tracking
            'google-analytics': [
                {'type': 'script', 'pattern': r'google-analytics.com'},
                {'type': 'script', 'pattern': r'ga\(\'create\''},
                {'type': 'script', 'pattern': r'gtag'},
            ],
            'google-tag-manager': [
                {'type': 'script', 'pattern': r'googletagmanager.com'},
                {'type': 'script', 'pattern': r'gtm.js'},
            ],
            
            # CDNs
            'cloudfront': [
                {'type': 'header', 'pattern': r'cloudfront', 'header': 'via'},
                {'type': 'header', 'pattern': r'cloudfront', 'header': 'x-amz-cf-id'},
            ],
            'fastly': [
                {'type': 'header', 'pattern': r'fastly', 'header': 'via'},
                {'type': 'header', 'pattern': r'fastly', 'header': 'x-served-by'},
            ],
            'akamai': [
                {'type': 'header', 'pattern': r'akamai', 'header': 'server'},
                {'type': 'header', 'pattern': r'akamai', 'header': 'x-akamai-transformed'},
            ],
            
            # Security
            'waf': [
                {'type': 'header', 'pattern': r'waf', 'header': 'server'},
                {'type': 'header', 'pattern': r'waf', 'header': 'x-powered-by'},
            ],
            'mod_security': [
                {'type': 'header', 'pattern': r'mod_security', 'header': 'server'},
                {'type': 'header', 'pattern': r'modsecurity', 'header': 'server'},
            ],
            'fail2ban': [
                {'type': 'header', 'pattern': r'fail2ban', 'header': 'server'},
            ],
        }

    def detect(self) -> Dict[str, Any]:
        """
        Detect technologies used by the web application.

        Returns:
            Dict[str, Any]: A dictionary containing detected technologies and related information.
        """
        print(f"[+] Detecting technologies on {self.target}")
        
        try:
            # Make sure the target has a scheme
            if not self.target.startswith(('http://', 'https://')):
                self.target = 'http://' + self.target
            
            # Fetch the web page
            self._fetch_page()
            
            # Parse the HTML content
            self._parse_html()
            
            # Detect technologies
            self._detect_from_headers()
            self._detect_from_cookies()
            self._detect_from_html()
            self._detect_from_scripts()
            self._detect_from_meta_tags()
            
            # Prepare the result
            result = {
                "target": self.target,
                "technologies": sorted(list(self.technologies)),
                "headers": self.headers,
                "cookies": self.cookies,
                "meta_tags": self.meta_tags,
                "scripts": self.scripts[:10]  # Limit to first 10 scripts for brevity
            }
            
            print(f"[+] Detected {len(result['technologies'])} technologies: {', '.join(result['technologies'])}")
            
            return result
        
        except Exception as e:
            print(f"[!] Error detecting technologies: {e}", file=sys.stderr)
            return {
                "target": self.target,
                "technologies": [],
                "error": str(e)
            }

    def _fetch_page(self) -> None:
        """
        Fetch the web page and store headers, cookies, and HTML content.
        """
        try:
            response = requests.get(
                self.target,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
            )
            
            self.headers = dict(response.headers)
            self.html_content = response.text
            self.cookies = dict(response.cookies)
            
            print(f"[+] Fetched page: {len(self.html_content)} bytes, status {response.status_code}")
        
        except Exception as e:
            print(f"[!] Error fetching page: {e}", file=sys.stderr)
            raise

    def _parse_html(self) -> None:
        """
        Parse the HTML content to extract scripts and meta tags.
        """
        try:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            
            # Extract scripts
            for script in soup.find_all('script', src=True):
                self.scripts.append(script['src'])
            
            # Extract meta tags
            for meta in soup.find_all('meta'):
                meta_dict = {}
                for attr in meta.attrs:
                    meta_dict[attr] = meta[attr]
                self.meta_tags.append(meta_dict)
            
            print(f"[+] Parsed HTML: found {len(self.scripts)} scripts and {len(self.meta_tags)} meta tags")
        
        except Exception as e:
            print(f"[!] Error parsing HTML: {e}", file=sys.stderr)

    def _detect_from_headers(self) -> None:
        """
        Detect technologies from HTTP headers.
        """
        for tech, signatures in self.signatures.items():
            for signature in signatures:
                if signature['type'] == 'header' and 'header' in signature:
                    header_name = signature['header'].lower()
                    if header_name in {k.lower(): k for k in self.headers}:
                        actual_key = {k.lower(): k for k in self.headers}[header_name]
                        header_value = self.headers[actual_key].lower()
                        if re.search(signature['pattern'], header_value, re.IGNORECASE):
                            self.technologies.add(tech)
                            print(f"[+] Detected {tech} from header {header_name}")

    def _detect_from_cookies(self) -> None:
        """
        Detect technologies from cookies.
        """
        for tech, signatures in self.signatures.items():
            for signature in signatures:
                if signature['type'] == 'cookie':
                    for cookie_name in self.cookies:
                        if re.search(signature['pattern'], cookie_name, re.IGNORECASE):
                            self.technologies.add(tech)
                            print(f"[+] Detected {tech} from cookie {cookie_name}")

    def _detect_from_html(self) -> None:
        """
        Detect technologies from HTML content.
        """
        for tech, signatures in self.signatures.items():
            for signature in signatures:
                if signature['type'] == 'html':
                    if re.search(signature['pattern'], self.html_content, re.IGNORECASE):
                        self.technologies.add(tech)
                        print(f"[+] Detected {tech} from HTML content")

    def _detect_from_scripts(self) -> None:
        """
        Detect technologies from script tags.
        """
        for tech, signatures in self.signatures.items():
            for signature in signatures:
                if signature['type'] == 'script':
                    for script in self.scripts:
                        if re.search(signature['pattern'], script, re.IGNORECASE):
                            self.technologies.add(tech)
                            print(f"[+] Detected {tech} from script {script}")

    def _detect_from_meta_tags(self) -> None:
        """
        Detect technologies from meta tags.
        """
        for tech, signatures in self.signatures.items():
            for signature in signatures:
                if signature['type'] == 'meta' and 'name' in signature:
                    for meta in self.meta_tags:
                        if 'name' in meta and meta['name'].lower() == signature['name'].lower():
                            if 'content' in meta and re.search(signature['pattern'], meta['content'], re.IGNORECASE):
                                self.technologies.add(tech)
                                print(f"[+] Detected {tech} from meta tag {meta['name']}")


def detect_technologies(target: str) -> Dict[str, Any]:
    """
    Convenience function to detect technologies used by a web application.

    Args:
        target (str): The target URL to analyze.

    Returns:
        Dict[str, Any]: A dictionary containing detected technologies and related information.
    """
    detector = TechnologyDetector(target)
    return detector.detect()


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        try:
            result = detect_technologies(target_url)
            print(f"\nTechnology detection results for {target_url}:")
            print(json.dumps(result, indent=2))
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    else:
        print("Usage: python tech_detector.py <target_url>", file=sys.stderr)
