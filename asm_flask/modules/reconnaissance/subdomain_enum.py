#!/usr/bin/env python3
"""
Subdomain Enumeration Module for Attack Surface Monitoring Tool
This module handles subdomain discovery using various techniques and tools.
"""

import subprocess
import json
import requests
import dns.resolver
import sys
import os
from typing import List, Dict, Any, Set
from concurrent.futures import ThreadPoolExecutor, as_completed


class SubdomainEnumerator:
    """
    A class to handle subdomain enumeration using various techniques.
    """

    def __init__(self, domain: str, max_threads: int = 10):
        """
        Initialize the SubdomainEnumerator with the target domain.

        Args:
            domain (str): The target domain to enumerate subdomains for.
            max_threads (int): Maximum number of threads for concurrent operations.
        """
        self.domain = domain
        self.max_threads = max_threads
        self.subdomains: Set[str] = set()

    def enumerate_subdomains(self) -> List[str]:
        """
        Perform subdomain enumeration using multiple techniques.

        Returns:
            List[str]: A list of discovered subdomains.
        """
        # Use multiple techniques to discover subdomains
        self._dns_bruteforce()
        self._search_crtsh()
        self._search_dns_dumpster()
        
        # Convert set to sorted list
        return sorted(list(self.subdomains))

    def _dns_bruteforce(self) -> None:
        """
        Perform DNS bruteforce using common subdomain wordlists.
        """
        # Common subdomains to check
        common_subdomains = [
            "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", 
            "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal", 
            "ns", "ww1", "host", "support", "dev", "web", "bbs", "ww42", "mx", "email",
            "cloud", "1", "2", "forum", "owa", "www2", "gw", "admin", "store", "mx1",
            "cdn", "api", "exchange", "app", "gov", "2tty", "vps", "govyty", "hgfgdf",
            "news", "1rer", "lkjkui"
        ]

        print(f"[+] Starting DNS bruteforce for {self.domain}")
        
        def check_subdomain(subdomain):
            try:
                # Construct the full domain
                full_domain = f"{subdomain}.{self.domain}"
                
                # Try to resolve the domain
                dns.resolver.resolve(full_domain, 'A')
                return full_domain
            except:
                return None

        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_subdomain = {executor.submit(check_subdomain, subdomain): subdomain for subdomain in common_subdomains}
            
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    self.subdomains.add(result)
                    print(f"[+] Discovered subdomain: {result}")

    def _search_crtsh(self) -> None:
        """
        Search for subdomains using Certificate Transparency logs (crt.sh).
        """
        print(f"[+] Searching crt.sh for {self.domain}")
        
        try:
            # Query crt.sh for the domain
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract unique subdomains
                for entry in data:
                    name = entry.get('name_value', '')
                    
                    # Split by newlines and process each
                    for domain in name.split('\n'):
                        # Remove wildcard and clean
                        clean_domain = domain.strip().replace('*.', '')
                        
                        # Ensure it's a subdomain of our target
                        if clean_domain.endswith(f".{self.domain}"):
                            self.subdomains.add(clean_domain)
                            print(f"[+] Discovered subdomain from crt.sh: {clean_domain}")
        
        except Exception as e:
            print(f"[!] Error querying crt.sh: {e}", file=sys.stderr)

    def _search_dns_dumpster(self) -> None:
        """
        Search for subdomains using DNS Dumpster API simulation.
        """
        print(f"[+] Simulating DNS Dumpster search for {self.domain}")
        
        # Since we can't directly use the DNS Dumpster API, we'll simulate it
        # by checking some common DNS records that might reveal subdomains
        
        try:
            # Check for common DNS records
            for record_type in ['MX', 'NS', 'TXT']:
                try:
                    answers = dns.resolver.resolve(self.domain, record_type)
                    
                    for answer in answers:
                        # Extract potential subdomains from records
                        answer_text = answer.to_text()
                        
                        # For MX records, extract the mail server domain
                        if record_type == 'MX':
                            parts = answer_text.split(' ')
                            if len(parts) > 1:
                                mx_domain = parts[1].rstrip('.')
                                if mx_domain.endswith(self.domain):
                                    self.subdomains.add(mx_domain)
                                    print(f"[+] Discovered subdomain from MX record: {mx_domain}")
                        
                        # For NS records, extract the nameserver domain
                        elif record_type == 'NS':
                            ns_domain = answer_text.rstrip('.')
                            if ns_domain.endswith(self.domain):
                                self.subdomains.add(ns_domain)
                                print(f"[+] Discovered subdomain from NS record: {ns_domain}")
                
                except Exception:
                    pass
        
        except Exception as e:
            print(f"[!] Error in DNS Dumpster simulation: {e}", file=sys.stderr)


def enumerate_subdomains(domain: str) -> List[str]:
    """
    Convenience function to enumerate subdomains for a given domain.

    Args:
        domain (str): The target domain to enumerate subdomains for.

    Returns:
        List[str]: A list of discovered subdomains.
    """
    enumerator = SubdomainEnumerator(domain)
    return enumerator.enumerate_subdomains()


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 1:
        target_domain = sys.argv[1]
        try:
            discovered_subdomains = enumerate_subdomains(target_domain)
            print(f"\nFound {len(discovered_subdomains)} subdomains for {target_domain}:")
            for subdomain in discovered_subdomains:
                print(f" - {subdomain}")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    else:
        print("Usage: python subdomain_enum.py <domain>", file=sys.stderr)
