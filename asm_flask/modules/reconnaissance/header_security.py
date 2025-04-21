#!/usr/bin/env python3
"""
HTTP Header Security Audit Module for Attack Surface Monitoring Tool
This module analyzes HTTP security headers for web applications.
"""

import requests
import json
import sys
from typing import Dict, Any, List, Optional
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class HeaderSecurityAuditor:
    """
    A class to audit HTTP security headers of web applications.
    """

    def __init__(self, target: str, timeout: int = 10):
        """
        Initialize the HeaderSecurityAuditor with the target URL.

        Args:
            target (str): The target URL to analyze.
            timeout (int): Timeout in seconds for HTTP requests.
        """
        self.target = target
        self.timeout = timeout
        
        # Define security headers and their importance
        self.security_headers = {
            'strict-transport-security': {
                'description': 'HTTP Strict Transport Security (HSTS)',
                'importance': 'high',
                'expected': 'max-age=31536000; includeSubDomains; preload',
                'regex': r'max-age=(\d+)',
                'min_value': 15768000  # 6 months in seconds
            },
            'content-security-policy': {
                'description': 'Content Security Policy (CSP)',
                'importance': 'high',
                'expected': 'default-src \'self\'',
                'regex': None
            },
            'x-content-type-options': {
                'description': 'X-Content-Type-Options',
                'importance': 'medium',
                'expected': 'nosniff',
                'regex': None
            },
            'x-frame-options': {
                'description': 'X-Frame-Options',
                'importance': 'high',
                'expected': 'DENY or SAMEORIGIN',
                'regex': None
            },
            'x-xss-protection': {
                'description': 'X-XSS-Protection',
                'importance': 'medium',
                'expected': '1; mode=block',
                'regex': None
            },
            'referrer-policy': {
                'description': 'Referrer-Policy',
                'importance': 'medium',
                'expected': 'no-referrer, strict-origin or strict-origin-when-cross-origin',
                'regex': None
            },
            'permissions-policy': {
                'description': 'Permissions-Policy',
                'importance': 'medium',
                'expected': 'Present with appropriate restrictions',
                'regex': None
            },
            'cache-control': {
                'description': 'Cache-Control',
                'importance': 'medium',
                'expected': 'no-store, max-age=0',
                'regex': None
            },
            'clear-site-data': {
                'description': 'Clear-Site-Data',
                'importance': 'low',
                'expected': '"cache", "cookies", "storage"',
                'regex': None
            },
            'cross-origin-embedder-policy': {
                'description': 'Cross-Origin-Embedder-Policy',
                'importance': 'low',
                'expected': 'require-corp',
                'regex': None
            },
            'cross-origin-opener-policy': {
                'description': 'Cross-Origin-Opener-Policy',
                'importance': 'low',
                'expected': 'same-origin',
                'regex': None
            },
            'cross-origin-resource-policy': {
                'description': 'Cross-Origin-Resource-Policy',
                'importance': 'low',
                'expected': 'same-origin',
                'regex': None
            },
            'access-control-allow-origin': {
                'description': 'Access-Control-Allow-Origin',
                'importance': 'medium',
                'expected': 'Specific origin or null, not *',
                'regex': None
            },
            'server': {
                'description': 'Server',
                'importance': 'low',
                'expected': 'Not present or minimal information',
                'regex': None,
                'negative': True  # This header should ideally not be present
            },
            'x-powered-by': {
                'description': 'X-Powered-By',
                'importance': 'low',
                'expected': 'Not present',
                'regex': None,
                'negative': True  # This header should ideally not be present
            }
        }

    def audit(self) -> Dict[str, Any]:
        """
        Audit HTTP security headers.

        Returns:
            Dict[str, Any]: A dictionary containing audit results.
        """
        print(f"[+] Auditing HTTP security headers for {self.target}")
        
        result = {
            "target": self.target,
            "headers": {},
            "missing_headers": [],
            "insecure_headers": [],
            "score": 0,
            "max_score": 0,
            "grade": "F"
        }
        
        try:
            # Make sure the target has a scheme
            if not self.target.startswith(('http://', 'https://')):
                self.target = 'https://' + self.target
                # Try HTTPS first, fallback to HTTP if needed
                try:
                    response = self._fetch_headers(self.target)
                except:
                    self.target = 'http://' + self.target.replace('https://', '')
                    response = self._fetch_headers(self.target)
            else:
                response = self._fetch_headers(self.target)
            
            # Store all headers
            result["headers"] = dict(response.headers)
            
            # Analyze security headers
            score, max_score, missing, insecure = self._analyze_headers(response.headers)
            
            result["missing_headers"] = missing
            result["insecure_headers"] = insecure
            result["score"] = score
            result["max_score"] = max_score
            result["grade"] = self._calculate_grade(score, max_score)
            
            print(f"[+] Header security audit complete: Grade {result['grade']}, Score {score}/{max_score}")
            print(f"[+] Missing headers: {', '.join(missing) if missing else 'None'}")
            
            return result
        
        except Exception as e:
            print(f"[!] Error auditing headers: {e}", file=sys.stderr)
            return {
                "target": self.target,
                "headers": {},
                "missing_headers": list(self.security_headers.keys()),
                "insecure_headers": [],
                "score": 0,
                "max_score": 100,
                "grade": "F",
                "error": str(e)
            }

    def _fetch_headers(self, url: str) -> requests.Response:
        """
        Fetch HTTP headers from the target URL.

        Args:
            url (str): The URL to fetch headers from.

        Returns:
            requests.Response: The HTTP response.
        """
        response = requests.get(
            url,
            timeout=self.timeout,
            verify=False,
            allow_redirects=True,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        )
        
        print(f"[+] Fetched headers from {url}: status {response.status_code}")
        
        return response

    def _analyze_headers(self, headers: Dict[str, str]) -> tuple:
        """
        Analyze HTTP security headers.

        Args:
            headers (Dict[str, str]): The HTTP headers to analyze.

        Returns:
            tuple: (score, max_score, missing_headers, insecure_headers)
        """
        score = 0
        max_score = 0
        missing_headers = []
        insecure_headers = []
        
        # Convert headers to lowercase for case-insensitive comparison
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Check each security header
        for header, config in self.security_headers.items():
            # Determine weight based on importance
            weight = 10 if config['importance'] == 'high' else 5 if config['importance'] == 'medium' else 2
            max_score += weight
            
            # Check if header is present
            if header in headers_lower:
                value = headers_lower[header]
                
                # For negative headers (those that should not be present)
                if config.get('negative', False):
                    insecure_headers.append(f"{header}: {value}")
                    print(f"[!] Insecure header present: {header}: {value}")
                    continue
                
                # Check if the value matches expected pattern
                if config['regex']:
                    import re
                    match = re.search(config['regex'], value)
                    if match:
                        # For HSTS, check if max-age is sufficient
                        if header == 'strict-transport-security':
                            max_age = int(match.group(1))
                            if max_age >= config['min_value']:
                                score += weight
                            else:
                                insecure_headers.append(f"{header}: {value} (max-age too short)")
                                print(f"[!] Insecure header value: {header}: {value} (max-age too short)")
                    else:
                        insecure_headers.append(f"{header}: {value}")
                        print(f"[!] Insecure header value: {header}: {value}")
                else:
                    # For headers without regex, just award points for presence
                    score += weight
                    print(f"[+] Secure header present: {header}")
            else:
                missing_headers.append(header)
                print(f"[!] Missing security header: {header}")
        
        return score, max_score, missing_headers, insecure_headers

    def _calculate_grade(self, score: int, max_score: int) -> str:
        """
        Calculate a grade based on the score.

        Args:
            score (int): The score achieved.
            max_score (int): The maximum possible score.

        Returns:
            str: A grade from A+ to F.
        """
        if max_score == 0:
            return "F"
        
        percentage = (score / max_score) * 100
        
        if percentage >= 95:
            return "A+"
        elif percentage >= 90:
            return "A"
        elif percentage >= 85:
            return "A-"
        elif percentage >= 80:
            return "B+"
        elif percentage >= 75:
            return "B"
        elif percentage >= 70:
            return "B-"
        elif percentage >= 65:
            return "C+"
        elif percentage >= 60:
            return "C"
        elif percentage >= 55:
            return "C-"
        elif percentage >= 50:
            return "D+"
        elif percentage >= 45:
            return "D"
        elif percentage >= 40:
            return "D-"
        else:
            return "F"


def audit_headers(target: str) -> Dict[str, Any]:
    """
    Convenience function to audit HTTP security headers.

    Args:
        target (str): The target URL to analyze.

    Returns:
        Dict[str, Any]: A dictionary containing audit results.
    """
    auditor = HeaderSecurityAuditor(target)
    return auditor.audit()


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        try:
            result = audit_headers(target_url)
            print(f"\nHTTP header security audit results for {target_url}:")
            print(f"Grade: {result['grade']}")
            print(f"Score: {result['score']}/{result['max_score']}")
            print(f"Missing headers: {', '.join(result['missing_headers']) if result['missing_headers'] else 'None'}")
            print(f"Insecure headers: {', '.join(result['insecure_headers']) if result['insecure_headers'] else 'None'}")
            print("\nAll headers:")
            for header, value in result['headers'].items():
                print(f"  {header}: {value}")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    else:
        print("Usage: python header_security.py <target_url>", file=sys.stderr)
