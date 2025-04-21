#!/usr/bin/env python3
"""
Live Subdomain Detection Module for Attack Surface Monitoring Tool
This module checks which subdomains are alive and responding to HTTP/HTTPS requests.
"""

import requests
import socket
import concurrent.futures
import sys
from typing import List, Dict, Any, Tuple
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class LiveSubdomainDetector:
    """
    A class to check if subdomains are alive and responding to HTTP/HTTPS requests.
    """

    def __init__(self, subdomains: List[str], max_threads: int = 10, timeout: int = 5):
        """
        Initialize the LiveSubdomainDetector with a list of subdomains.

        Args:
            subdomains (List[str]): List of subdomains to check.
            max_threads (int): Maximum number of threads for concurrent operations.
            timeout (int): Timeout in seconds for HTTP requests.
        """
        self.subdomains = subdomains
        self.max_threads = max_threads
        self.timeout = timeout
        self.results: List[Dict[str, Any]] = []

    def check_live_subdomains(self) -> List[Dict[str, Any]]:
        """
        Check which subdomains are alive and responding to HTTP/HTTPS requests.

        Returns:
            List[Dict[str, Any]]: A list of dictionaries containing information about live subdomains.
        """
        print(f"[+] Checking {len(self.subdomains)} subdomains for live status")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_subdomain = {executor.submit(self._check_subdomain, subdomain): subdomain for subdomain in self.subdomains}
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    result = future.result()
                    if result:
                        self.results.append(result)
                        print(f"[+] Live subdomain: {subdomain} - Status: {result['status_code']} - Server: {result.get('server', 'Unknown')}")
                except Exception as e:
                    print(f"[!] Error checking {subdomain}: {e}", file=sys.stderr)
        
        return self.results

    def _check_subdomain(self, subdomain: str) -> Dict[str, Any]:
        """
        Check if a single subdomain is alive and responding to HTTP/HTTPS requests.

        Args:
            subdomain (str): The subdomain to check.

        Returns:
            Dict[str, Any]: A dictionary containing information about the subdomain if it's alive, None otherwise.
        """
        result = None
        
        # Try HTTPS first
        try:
            response = requests.get(f"https://{subdomain}", timeout=self.timeout, verify=False, allow_redirects=True)
            
            result = {
                "subdomain": subdomain,
                "protocol": "https",
                "status_code": response.status_code,
                "title": self._extract_title(response.text),
                "headers": dict(response.headers),
                "server": response.headers.get('Server', 'Unknown'),
                "content_type": response.headers.get('Content-Type', 'Unknown'),
                "redirect_url": response.url if response.url != f"https://{subdomain}" else None,
                "ip": self._get_ip(subdomain)
            }
            
            return result
        except requests.RequestException:
            # If HTTPS fails, try HTTP
            try:
                response = requests.get(f"http://{subdomain}", timeout=self.timeout, allow_redirects=True)
                
                result = {
                    "subdomain": subdomain,
                    "protocol": "http",
                    "status_code": response.status_code,
                    "title": self._extract_title(response.text),
                    "headers": dict(response.headers),
                    "server": response.headers.get('Server', 'Unknown'),
                    "content_type": response.headers.get('Content-Type', 'Unknown'),
                    "redirect_url": response.url if response.url != f"http://{subdomain}" else None,
                    "ip": self._get_ip(subdomain)
                }
                
                return result
            except requests.RequestException:
                # Try socket connection as a last resort
                if self._is_socket_alive(subdomain):
                    return {
                        "subdomain": subdomain,
                        "protocol": "socket_only",
                        "status_code": None,
                        "title": None,
                        "headers": {},
                        "server": "Unknown",
                        "content_type": "Unknown",
                        "redirect_url": None,
                        "ip": self._get_ip(subdomain)
                    }
        
        return None

    def _extract_title(self, html: str) -> str:
        """
        Extract the title from HTML content.

        Args:
            html (str): HTML content.

        Returns:
            str: The title if found, "No Title" otherwise.
        """
        try:
            start = html.find("<title>")
            end = html.find("</title>")
            if start != -1 and end != -1:
                return html[start + 7:end].strip()
        except:
            pass
        
        return "No Title"

    def _get_ip(self, domain: str) -> str:
        """
        Get the IP address for a domain.

        Args:
            domain (str): The domain to resolve.

        Returns:
            str: The IP address if resolved, "Unknown" otherwise.
        """
        try:
            return socket.gethostbyname(domain)
        except:
            return "Unknown"

    def _is_socket_alive(self, domain: str) -> bool:
        """
        Check if a domain is alive by attempting a socket connection.

        Args:
            domain (str): The domain to check.

        Returns:
            bool: True if the domain is alive, False otherwise.
        """
        try:
            # Try common ports
            for port in [80, 443, 8080, 8443]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((domain, port))
                    sock.close()
                    if result == 0:
                        return True
                except:
                    continue
            
            return False
        except:
            return False


def check_live_subdomains(subdomains: List[str]) -> List[Dict[str, Any]]:
    """
    Convenience function to check which subdomains are alive.

    Args:
        subdomains (List[str]): List of subdomains to check.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries containing information about live subdomains.
    """
    detector = LiveSubdomainDetector(subdomains)
    return detector.check_live_subdomains()


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 1:
        try:
            # Read subdomains from command line arguments
            test_subdomains = sys.argv[1:]
            
            # Check which subdomains are alive
            live_subdomains = check_live_subdomains(test_subdomains)
            
            print(f"\nFound {len(live_subdomains)} live subdomains:")
            for result in live_subdomains:
                print(f" - {result['subdomain']} ({result['ip']}) - {result['protocol']} - Status: {result['status_code']}")
        
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    else:
        print("Usage: python live_subdomain.py <subdomain1> <subdomain2> ...", file=sys.stderr)
