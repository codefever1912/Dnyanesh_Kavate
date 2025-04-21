#!/usr/bin/env python3
"""
OSINT / Breach Check Module for Attack Surface Monitoring Tool
This module checks for leaked emails/domains in data breaches.
"""

import requests
import sys
import json
import re
import time
import hashlib
from typing import Dict, Any, List, Set
from concurrent.futures import ThreadPoolExecutor, as_completed


class OSINTBreachChecker:
    """
    A class to check for leaked emails and domain information in data breaches.
    """

    def __init__(self, domain: str, max_threads: int = 5, delay: float = 1.0):
        """
        Initialize the OSINTBreachChecker with the target domain.

        Args:
            domain (str): The target domain to check.
            max_threads (int): Maximum number of threads for concurrent operations.
            delay (float): Delay between API requests in seconds.
        """
        self.domain = domain
        self.max_threads = max_threads
        self.delay = delay
        self.api_keys = {}  # Would store API keys if available
        self.email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        self.found_emails: Set[str] = set()
        self.breaches: List[Dict[str, Any]] = []

    def check_breaches(self) -> Dict[str, Any]:
        """
        Check for the domain and associated emails in data breaches.

        Returns:
            Dict[str, Any]: A dictionary containing breach information.
        """
        print(f"[+] Starting OSINT and breach check for {self.domain}")
        
        result = {
            "domain": self.domain,
            "emails_found": [],
            "breaches": [],
            "breach_count": 0,
            "data_sources": []
        }
        
        try:
            # First, find emails associated with the domain
            self._find_emails()
            result["emails_found"] = sorted(list(self.found_emails))
            
            print(f"[+] Found {len(self.found_emails)} email addresses for {self.domain}")
            
            # Check domain breaches
            domain_breaches = self._check_domain_breaches()
            if domain_breaches:
                self.breaches.extend(domain_breaches)
                result["data_sources"].append("Domain breach check")
            
            # Check email breaches
            if self.found_emails:
                email_breaches = self._check_email_breaches()
                if email_breaches:
                    self.breaches.extend(email_breaches)
                    result["data_sources"].append("Email breach check")
            
            # Check pastebin and similar sites
            pastebin_results = self._check_pastebin()
            if pastebin_results:
                self.breaches.extend(pastebin_results)
                result["data_sources"].append("Pastebin check")
            
            # Deduplicate breaches
            unique_breaches = []
            breach_ids = set()
            
            for breach in self.breaches:
                breach_id = breach.get("breach_id", "")
                if not breach_id:
                    breach_id = breach.get("source", "") + breach.get("title", "")
                
                if breach_id and breach_id not in breach_ids:
                    breach_ids.add(breach_id)
                    unique_breaches.append(breach)
            
            result["breaches"] = unique_breaches
            result["breach_count"] = len(unique_breaches)
            
            print(f"[+] Found {len(unique_breaches)} breaches for {self.domain}")
            
            return result
        
        except Exception as e:
            print(f"[!] Error checking breaches: {e}", file=sys.stderr)
            return {
                "domain": self.domain,
                "emails_found": sorted(list(self.found_emails)),
                "breaches": [],
                "breach_count": 0,
                "data_sources": [],
                "error": str(e)
            }

    def _find_emails(self) -> None:
        """
        Find email addresses associated with the domain.
        """
        # Since we don't have actual API keys for services like Hunter.io,
        # we'll simulate finding some common email patterns
        
        print(f"[+] Searching for email addresses for {self.domain}")
        
        # Common email patterns
        common_names = ["info", "admin", "contact", "support", "sales", "help",
                        "webmaster", "hostmaster", "postmaster", "security"]
        
        # Add some simulated emails
        for name in common_names:
            self.found_emails.add(f"{name}@{self.domain}")
        
        # Simulate finding emails from Google search
        self._simulate_google_search()
        
        # If we had API keys, we would use services like:
        # - Hunter.io
        # - Clearbit
        # - FullContact
        # - Email-format.com
        # - Skymem.info

    def _simulate_google_search(self) -> None:
        """
        Simulate finding emails from Google search.
        """
        # In a real implementation, we might use Google dorks or a search API
        # Here, we'll just simulate finding some additional emails
        
        # Generate some "realistic" looking emails based on the domain name
        domain_parts = self.domain.split('.')
        company_name = domain_parts[0]
        
        if len(company_name) > 4:
            # Generate emails based on company name
            if company_name.endswith('s'):
                company_name = company_name[:-1]
            
            # First name patterns
            first_names = ["john", "jane", "michael", "david", "sarah", "lisa", "robert", "james"]
            
            for first_name in first_names:
                # first.last@domain.com
                self.found_emails.add(f"{first_name}@{self.domain}")
                self.found_emails.add(f"{first_name}.{company_name}@{self.domain}")
                
                # first_last@domain.com
                self.found_emails.add(f"{first_name}_{company_name}@{self.domain}")
                
                # firstlast@domain.com
                self.found_emails.add(f"{first_name}{company_name}@{self.domain}")
                
                # first.initial@domain.com
                self.found_emails.add(f"{first_name}.{company_name[0]}@{self.domain}")

    def _check_domain_breaches(self) -> List[Dict[str, Any]]:
        """
        Check if the domain has been involved in any data breaches.

        Returns:
            List[Dict[str, Any]]: A list of breach information.
        """
        breaches = []
        
        print(f"[+] Checking domain breaches for {self.domain}")
        
        # Simulate checking Have I Been Pwned for the domain
        # In a real implementation, we would use the HIBP API with an API key
        
        # Simulate a response based on the domain
        domain_hash = hashlib.md5(self.domain.encode()).hexdigest()
        last_digit = int(domain_hash[-1], 16)
        
        # Simulate finding breaches based on the hash
        if last_digit % 3 == 0:  # Simulate finding breaches for some domains
            breach_count = last_digit % 5 + 1  # 1-5 breaches
            
            for i in range(breach_count):
                breach_date = f"2020-{(last_digit + i) % 12 + 1:02d}-{(last_digit + i*2) % 28 + 1:02d}"
                
                breach = {
                    "breach_id": f"breach_{domain_hash[:8]}_{i}",
                    "title": f"Simulated Breach {i+1}",
                    "domain": self.domain,
                    "breach_date": breach_date,
                    "added_date": breach_date,
                    "modified_date": breach_date,
                    "description": f"This is a simulated breach for demonstration purposes.",
                    "data_classes": ["Email addresses", "Passwords", "Names"],
                    "source": "Have I Been Pwned (Simulated)",
                    "verified": True
                }
                
                breaches.append(breach)
        
        return breaches

    def _check_email_breaches(self) -> List[Dict[str, Any]]:
        """
        Check if any of the found emails have been involved in data breaches.

        Returns:
            List[Dict[str, Any]]: A list of breach information.
        """
        breaches = []
        
        if not self.found_emails:
            return breaches
        
        print(f"[+] Checking email breaches for {len(self.found_emails)} emails")
        
        # In a real implementation, we would check each email with HIBP or similar services
        # Here, we'll simulate finding breaches for some emails
        
        # Process emails in parallel
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_email = {executor.submit(self._check_single_email, email): email for email in self.found_emails}
            
            for future in as_completed(future_to_email):
                email = future_to_email[future]
                try:
                    email_breaches = future.result()
                    if email_breaches:
                        breaches.extend(email_breaches)
                except Exception as e:
                    print(f"[!] Error checking breaches for {email}: {e}", file=sys.stderr)
        
        return breaches

    def _check_single_email(self, email: str) -> List[Dict[str, Any]]:
        """
        Check a single email for breaches.

        Args:
            email (str): The email to check.

        Returns:
            List[Dict[str, Any]]: A list of breach information.
        """
        breaches = []
        
        # Add delay to avoid rate limiting
        time.sleep(self.delay)
        
        # Simulate checking Have I Been Pwned for the email
        # In a real implementation, we would use the HIBP API with an API key
        
        # Simulate a response based on the email
        email_hash = hashlib.md5(email.encode()).hexdigest()
        last_digit = int(email_hash[-1], 16)
        
        # Simulate finding breaches based on the hash
        if last_digit % 4 == 0:  # Simulate finding breaches for some emails
            breach_count = last_digit % 3 + 1  # 1-3 breaches
            
            for i in range(breach_count):
                breach_date = f"2019-{(last_digit + i) % 12 + 1:02d}-{(last_digit + i*3) % 28 + 1:02d}"
                
                breach = {
                    "breach_id": f"email_breach_{email_hash[:8]}_{i}",
                    "title": f"Email Breach {i+1}",
                    "email": email,
                    "breach_date": breach_date,
                    "added_date": breach_date,
                    "modified_date": breach_date,
                    "description": f"This is a simulated email breach for demonstration purposes.",
                    "data_classes": ["Email addresses", "Passwords"],
                    "source": "Have I Been Pwned Email Check (Simulated)",
                    "verified": True
                }
                
                breaches.append(breach)
        
        return breaches

    def _check_pastebin(self) -> List[Dict[str, Any]]:
        """
        Check if the domain or emails appear in pastebin dumps.

        Returns:
            List[Dict[str, Any]]: A list of breach information.
        """
        breaches = []
        
        print(f"[+] Checking pastebin for {self.domain}")
        
        # In a real implementation, we would use services like:
        # - Pastebin
        # - Ghostbin
        # - Slexy
        # - Pastie
        
        # Simulate finding pastes
        domain_hash = hashlib.md5(self.domain.encode()).hexdigest()
        last_digit = int(domain_hash[-1], 16)
        
        # Simulate finding pastes based on the hash
        if last_digit % 5 == 0:  # Simulate finding pastes for some domains
            paste_count = last_digit % 2 + 1  # 1-2 pastes
            
            for i in range(paste_count):
                paste_date = f"2021-{(last_digit + i) % 12 + 1:02d}-{(last_digit + i*4) % 28 + 1:02d}"
                
                paste = {
                    "breach_id": f"paste_{domain_hash[:8]}_{i}",
                    "title": f"Pastebin Leak {i+1}",
                    "domain": self.domain,
                    "breach_date": paste_date,
                    "added_date": paste_date,
                    "modified_date": paste_date,
                    "description": f"This is a simulated pastebin leak for demonstration purposes.",
                    "data_classes": ["Email addresses", "API Keys", "Source Code"],
                    "source": "Pastebin (Simulated)",
                    "verified": False
                }
                
                breaches.append(paste)
        
        return breaches


def check_breaches(domain: str) -> Dict[str, Any]:
    """
    Convenience function to check for domain and email breaches.

    Args:
        domain (str): The target domain to check.

    Returns:
        Dict[str, Any]: A dictionary containing breach information.
    """
    checker = OSINTBreachChecker(domain)
    return checker.check_breaches()


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 1:
        target_domain = sys.argv[1]
        try:
            result = check_breaches(target_domain)
            print(f"\nOSINT and breach check results for {target_domain}:")
            print(f"Emails found: {len(result['emails_found'])}")
            print(f"Breaches found: {result['breach_count']}")
            print(f"Data sources: {', '.join(result['data_sources'])}")
            
            if result['emails_found']:
                print("\nEmails:")
                for email in result['emails_found'][:10]:  # Show first 10
                    print(f"  {email}")
                if len(result['emails_found']) > 10:
                    print(f"  ... and {len(result['emails_found']) - 10} more")
            
            if result['breaches']:
                print("\nBreaches:")
                for breach in result['breaches'][:5]:  # Show first 5
                    print(f"  {breach['title']} - {breach['breach_date']} - {breach['source']}")
                    print(f"    Data: {', '.join(breach['data_classes'])}")
                if len(result['breaches']) > 5:
                    print(f"  ... and {len(result['breaches']) - 5} more")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    else:
        print("Usage: python osint_breach.py <domain>", file=sys.stderr)
