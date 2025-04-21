#!/usr/bin/env python3
"""
WHOIS & DNS Records Module for Attack Surface Monitoring Tool
This module fetches WHOIS information and DNS records for domains.
"""

import whois
import dns.resolver
import sys
import json
from typing import Dict, Any, List, Optional
from datetime import datetime


class WhoisDNSAnalyzer:
    """
    A class to fetch and analyze WHOIS and DNS records for a domain.
    """

    def __init__(self, domain: str):
        """
        Initialize the WhoisDNSAnalyzer with the target domain.

        Args:
            domain (str): The target domain to analyze.
        """
        self.domain = domain
        self.dns_record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        self.spf_record = None
        self.dkim_record = None
        self.dmarc_record = None

    def get_whois_info(self) -> Dict[str, Any]:
        """
        Fetch WHOIS information for the domain.

        Returns:
            Dict[str, Any]: A dictionary containing WHOIS information.
        """
        print(f"[+] Fetching WHOIS information for {self.domain}")
        
        try:
            w = whois.whois(self.domain)
            
            # Convert dates to strings for JSON serialization
            whois_data = {}
            for key, value in w.items():
                if isinstance(value, datetime):
                    whois_data[key] = value.isoformat()
                elif isinstance(value, list) and value and isinstance(value[0], datetime):
                    whois_data[key] = [d.isoformat() for d in value]
                else:
                    whois_data[key] = value
            
            return whois_data
        
        except Exception as e:
            print(f"[!] Error fetching WHOIS information: {e}", file=sys.stderr)
            return {"error": str(e)}

    def get_dns_records(self) -> Dict[str, Any]:
        """
        Fetch DNS records for the domain.

        Returns:
            Dict[str, Any]: A dictionary containing DNS records.
        """
        print(f"[+] Fetching DNS records for {self.domain}")
        
        dns_records = {}
        
        for record_type in self.dns_record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                dns_records[record_type] = [answer.to_text() for answer in answers]
                print(f"[+] Found {len(dns_records[record_type])} {record_type} records")
            except dns.resolver.NoAnswer:
                dns_records[record_type] = []
            except dns.resolver.NXDOMAIN:
                print(f"[!] Domain {self.domain} does not exist", file=sys.stderr)
                dns_records[record_type] = []
            except Exception as e:
                print(f"[!] Error fetching {record_type} records: {e}", file=sys.stderr)
                dns_records[record_type] = []
        
        # Fetch SPF, DKIM, and DMARC records
        self._get_spf_record()
        self._get_dkim_record()
        self._get_dmarc_record()
        
        # Add email security records
        dns_records['SPF'] = [self.spf_record] if self.spf_record else []
        dns_records['DKIM'] = [self.dkim_record] if self.dkim_record else []
        dns_records['DMARC'] = [self.dmarc_record] if self.dmarc_record else []
        
        return dns_records

    def _get_spf_record(self) -> None:
        """
        Fetch SPF record for the domain.
        """
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')
            for answer in answers:
                txt_record = answer.to_text()
                if 'v=spf1' in txt_record:
                    self.spf_record = txt_record
                    print(f"[+] Found SPF record: {txt_record}")
                    break
        except Exception:
            pass

    def _get_dkim_record(self) -> None:
        """
        Fetch DKIM record for the domain.
        """
        # Common DKIM selectors
        selectors = ['default', 'dkim', 'mail', 'email', 'selector1', 'selector2', 'k1']
        
        for selector in selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{self.domain}"
                answers = dns.resolver.resolve(dkim_domain, 'TXT')
                for answer in answers:
                    txt_record = answer.to_text()
                    if 'v=DKIM1' in txt_record:
                        self.dkim_record = f"{dkim_domain}: {txt_record}"
                        print(f"[+] Found DKIM record for selector '{selector}': {txt_record}")
                        return
            except Exception:
                continue

    def _get_dmarc_record(self) -> None:
        """
        Fetch DMARC record for the domain.
        """
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for answer in answers:
                txt_record = answer.to_text()
                if 'v=DMARC1' in txt_record:
                    self.dmarc_record = txt_record
                    print(f"[+] Found DMARC record: {txt_record}")
                    break
        except Exception:
            pass

    def analyze(self) -> Dict[str, Any]:
        """
        Perform a complete WHOIS and DNS analysis.

        Returns:
            Dict[str, Any]: A dictionary containing all WHOIS and DNS information.
        """
        result = {
            "domain": self.domain,
            "whois": self.get_whois_info(),
            "dns_records": self.get_dns_records()
        }
        
        return result


def analyze_domain(domain: str) -> Dict[str, Any]:
    """
    Convenience function to perform WHOIS and DNS analysis for a domain.

    Args:
        domain (str): The target domain to analyze.

    Returns:
        Dict[str, Any]: A dictionary containing all WHOIS and DNS information.
    """
    analyzer = WhoisDNSAnalyzer(domain)
    return analyzer.analyze()


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 1:
        target_domain = sys.argv[1]
        try:
            result = analyze_domain(target_domain)
            print(f"\nWHOIS and DNS analysis for {target_domain}:")
            print(json.dumps(result, indent=2))
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    else:
        print("Usage: python whois_dns.py <domain>", file=sys.stderr)
