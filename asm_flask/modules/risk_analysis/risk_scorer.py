#!/usr/bin/env python3
"""
Risk Scoring Module for Attack Surface Monitoring Tool
This module calculates risk scores based on reconnaissance findings.
"""

import json
import sys
from typing import Dict, Any, List, Optional, Tuple
import math


class RiskScorer:
    """
    A class to calculate risk scores based on reconnaissance findings.
    """

    def __init__(self, domain: str, recon_data: Dict[str, Any]):
        """
        Initialize the RiskScorer with reconnaissance data.

        Args:
            domain (str): The target domain.
            recon_data (Dict[str, Any]): Reconnaissance data for the domain.
        """
        self.domain = domain
        self.recon_data = recon_data
        
        # Define risk weights for different findings
        self.risk_weights = {
            # Subdomain related risks
            'subdomain_count': {
                'weight': 5,
                'threshold': 20,  # More subdomains = more attack surface
                'description': 'Large number of subdomains increases attack surface'
            },
            
            # Port and service related risks
            'open_ports': {
                'weight': 10,
                'threshold': 10,  # More open ports = more attack surface
                'description': 'Open ports increase attack surface'
            },
            'critical_ports': {
                'weight': 15,
                'services': [21, 22, 23, 25, 53, 445, 3389, 3306, 5432],
                'description': 'Critical services exposed to the internet'
            },
            'outdated_services': {
                'weight': 20,
                'description': 'Outdated or vulnerable services detected'
            },
            
            # SSL/TLS related risks
            'ssl_issues': {
                'weight': 15,
                'description': 'SSL/TLS configuration issues'
            },
            'weak_cipher': {
                'weight': 20,
                'description': 'Weak SSL/TLS ciphers in use'
            },
            'expired_cert': {
                'weight': 25,
                'description': 'Expired SSL certificate'
            },
            'self_signed_cert': {
                'weight': 15,
                'description': 'Self-signed SSL certificate'
            },
            
            # HTTP header related risks
            'missing_security_headers': {
                'weight': 10,
                'headers': ['strict-transport-security', 'content-security-policy', 
                           'x-content-type-options', 'x-frame-options'],
                'description': 'Missing critical security headers'
            },
            
            # Technology related risks
            'outdated_cms': {
                'weight': 20,
                'description': 'Outdated CMS or framework detected'
            },
            'vulnerable_tech': {
                'weight': 15,
                'description': 'Technologies with known vulnerabilities'
            },
            
            # Sensitive path related risks
            'sensitive_paths': {
                'weight': 15,
                'threshold': 5,  # More sensitive paths = higher risk
                'description': 'Sensitive paths or directories exposed'
            },
            'high_sensitivity_paths': {
                'weight': 25,
                'description': 'Highly sensitive paths exposed (admin, config, etc.)'
            },
            
            # OSINT and breach related risks
            'breach_count': {
                'weight': 15,
                'threshold': 1,  # Any breach is concerning
                'description': 'Domain or emails found in data breaches'
            },
            'credential_leak': {
                'weight': 25,
                'description': 'Credentials found in data breaches'
            }
        }

    def calculate_risk_score(self) -> Dict[str, Any]:
        """
        Calculate the risk score based on reconnaissance findings.

        Returns:
            Dict[str, Any]: A dictionary containing the risk score and details.
        """
        print(f"[+] Calculating risk score for {self.domain}")
        
        # Initialize risk details
        risk_details = []
        total_risk_score = 0
        max_possible_score = 0
        
        # Process subdomain risks
        subdomain_risk, subdomain_details = self._calculate_subdomain_risks()
        total_risk_score += subdomain_risk
        risk_details.extend(subdomain_details)
        
        # Process port and service risks
        port_risk, port_details = self._calculate_port_risks()
        total_risk_score += port_risk
        risk_details.extend(port_details)
        
        # Process SSL/TLS risks
        ssl_risk, ssl_details = self._calculate_ssl_risks()
        total_risk_score += ssl_risk
        risk_details.extend(ssl_details)
        
        # Process HTTP header risks
        header_risk, header_details = self._calculate_header_risks()
        total_risk_score += header_risk
        risk_details.extend(header_details)
        
        # Process technology risks
        tech_risk, tech_details = self._calculate_technology_risks()
        total_risk_score += tech_risk
        risk_details.extend(tech_details)
        
        # Process sensitive path risks
        path_risk, path_details = self._calculate_path_risks()
        total_risk_score += path_risk
        risk_details.extend(path_details)
        
        # Process OSINT and breach risks
        osint_risk, osint_details = self._calculate_osint_risks()
        total_risk_score += osint_risk
        risk_details.extend(osint_details)
        
        # Calculate maximum possible score
        for detail in risk_details:
            max_possible_score += detail['max_score']
        
        # Normalize score to 0-100 range
        normalized_score = 0
        if max_possible_score > 0:
            normalized_score = min(100, int((total_risk_score / max_possible_score) * 100))
        
        # Sort risk details by score (highest first)
        risk_details.sort(key=lambda x: x['score'], reverse=True)
        
        # Prepare result
        result = {
            "domain": self.domain,
            "risk_score": normalized_score,
            "risk_level": self._get_risk_level(normalized_score),
            "risk_details": risk_details,
            "raw_score": total_risk_score,
            "max_possible_score": max_possible_score
        }
        
        print(f"[+] Risk score: {normalized_score}/100 ({result['risk_level']})")
        
        return result

    def _calculate_subdomain_risks(self) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Calculate risks related to subdomains.

        Returns:
            Tuple[float, List[Dict[str, Any]]]: Total risk score and risk details.
        """
        total_risk = 0
        risk_details = []
        
        # Check if subdomain data exists
        if 'subdomains' in self.recon_data and self.recon_data['subdomains']:
            subdomains = self.recon_data['subdomains']
            subdomain_count = len(subdomains)
            
            # Risk based on number of subdomains
            if subdomain_count > self.risk_weights['subdomain_count']['threshold']:
                score = min(self.risk_weights['subdomain_count']['weight'] * 
                           (subdomain_count / self.risk_weights['subdomain_count']['threshold']), 
                           self.risk_weights['subdomain_count']['weight'] * 2)
                
                total_risk += score
                risk_details.append({
                    'category': 'Subdomain',
                    'title': 'Large number of subdomains',
                    'description': f'Found {subdomain_count} subdomains, increasing the attack surface',
                    'score': score,
                    'max_score': self.risk_weights['subdomain_count']['weight'] * 2,
                    'affected_assets': [f"{subdomain_count} subdomains"]
                })
        
        return total_risk, risk_details

    def _calculate_port_risks(self) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Calculate risks related to open ports and services.

        Returns:
            Tuple[float, List[Dict[str, Any]]]: Total risk score and risk details.
        """
        total_risk = 0
        risk_details = []
        
        # Check if port scan data exists
        if 'open_ports' in self.recon_data and self.recon_data['open_ports']:
            open_ports = self.recon_data['open_ports']
            port_count = len(open_ports)
            
            # Risk based on number of open ports
            if port_count > 0:
                score = min(self.risk_weights['open_ports']['weight'] * 
                           (port_count / self.risk_weights['open_ports']['threshold']), 
                           self.risk_weights['open_ports']['weight'] * 2)
                
                total_risk += score
                risk_details.append({
                    'category': 'Port',
                    'title': 'Multiple open ports',
                    'description': f'Found {port_count} open ports, increasing the attack surface',
                    'score': score,
                    'max_score': self.risk_weights['open_ports']['weight'] * 2,
                    'affected_assets': [f"{port} ({service.get('service', 'unknown')})" 
                                       for port, service in enumerate(open_ports) if isinstance(service, dict)]
                })
            
            # Risk based on critical ports
            critical_ports = []
            for port_info in open_ports:
                if isinstance(port_info, dict) and 'port' in port_info:
                    port = int(port_info['port'])
                    if port in self.risk_weights['critical_ports']['services']:
                        service = port_info.get('service', 'unknown')
                        critical_ports.append(f"{port} ({service})")
            
            if critical_ports:
                score = self.risk_weights['critical_ports']['weight'] * min(1, len(critical_ports) / 3)
                
                total_risk += score
                risk_details.append({
                    'category': 'Port',
                    'title': 'Critical services exposed',
                    'description': 'Critical services are exposed to the internet',
                    'score': score,
                    'max_score': self.risk_weights['critical_ports']['weight'],
                    'affected_assets': critical_ports
                })
            
            # Risk based on outdated services
            outdated_services = []
            for port_info in open_ports:
                if isinstance(port_info, dict) and 'version' in port_info and port_info['version']:
                    # This is a simplified check - in a real scenario, we would compare against a database
                    # of known vulnerable versions
                    service = port_info.get('service', 'unknown')
                    version = port_info.get('version', '')
                    product = port_info.get('product', '')
                    
                    # Simple heuristic: versions with single digit are likely older
                    if version and (len(version.split('.')) == 1 or version.startswith('1.') or version.startswith('2.')):
                        outdated_services.append(f"{service} {product} {version} on port {port_info.get('port', 'unknown')}")
            
            if outdated_services:
                score = self.risk_weights['outdated_services']['weight'] * min(1, len(outdated_services) / 2)
                
                total_risk += score
                risk_details.append({
                    'category': 'Service',
                    'title': 'Outdated services',
                    'description': 'Outdated services may contain vulnerabilities',
                    'score': score,
                    'max_score': self.risk_weights['outdated_services']['weight'],
                    'affected_assets': outdated_services
                })
        
        return total_risk, risk_details

    def _calculate_ssl_risks(self) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Calculate risks related to SSL/TLS configuration.

        Returns:
            Tuple[float, List[Dict[str, Any]]]: Total risk score and risk details.
        """
        total_risk = 0
        risk_details = []
        
        # Check if SSL/TLS data exists
        if 'ssl_info' in self.recon_data and self.recon_data['ssl_info']:
            ssl_info = self.recon_data['ssl_info']
            
            # Check for SSL issues based on grade
            if 'grade' in ssl_info:
                grade = ssl_info['grade']
                if grade in ['F', 'D', 'C']:
                    score = self.risk_weights['ssl_issues']['weight'] * (1 - (ord(grade) - ord('C')) / 3)
                    
                    total_risk += score
                    risk_details.append({
                        'category': 'SSL/TLS',
                        'title': 'Poor SSL/TLS configuration',
                        'description': f'SSL/TLS configuration received a grade of {grade}',
                        'score': score,
                        'max_score': self.risk_weights['ssl_issues']['weight'],
                        'affected_assets': [self.domain]
                    })
            
            # Check for weak ciphers
            if 'vulnerabilities' in ssl_info and 'weak_cipher_suites' in ssl_info['vulnerabilities']:
                score = self.risk_weights['weak_cipher']['weight']
                
                total_risk += score
                risk_details.append({
                    'category': 'SSL/TLS',
                    'title': 'Weak SSL/TLS ciphers',
                    'description': 'Weak SSL/TLS ciphers may be vulnerable to attacks',
                    'score': score,
                    'max_score': self.risk_weights['weak_cipher']['weight'],
                    'affected_assets': [self.domain]
                })
            
            # Check for expired certificate
            if 'certificate' in ssl_info and ssl_info['certificate'].get('expired', False):
                score = self.risk_weights['expired_cert']['weight']
                
                total_risk += score
                risk_details.append({
                    'category': 'SSL/TLS',
                    'title': 'Expired SSL certificate',
                    'description': 'SSL certificate has expired',
                    'score': score,
                    'max_score': self.risk_weights['expired_cert']['weight'],
                    'affected_assets': [self.domain]
                })
            
            # Check for self-signed certificate
            if 'certificate' in ssl_info and ssl_info['certificate'].get('self_signed', False):
                score = self.risk_weights['self_signed_cert']['weight']
                
                total_risk += score
                risk_details.append({
                    'category': 'SSL/TLS',
                    'title': 'Self-signed SSL certificate',
                    'description': 'Self-signed certificates are not trusted by browsers',
                    'score': score,
                    'max_score': self.risk_weights['self_signed_cert']['weight'],
                    'affected_assets': [self.domain]
                })
        
        return total_risk, risk_details

    def _calculate_header_risks(self) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Calculate risks related to HTTP headers.

        Returns:
            Tuple[float, List[Dict[str, Any]]]: Total risk score and risk details.
        """
        total_risk = 0
        risk_details = []
        
        # Check if header data exists
        if 'headers' in self.recon_data and self.recon_data['headers']:
            headers_info = self.recon_data['headers']
            
            # Check for missing security headers
            if 'missing_headers' in headers_info:
                missing_headers = headers_info['missing_headers']
                critical_missing = [h for h in missing_headers 
                                   if h in self.risk_weights['missing_security_headers']['headers']]
                
                if critical_missing:
                    score = self.risk_weights['missing_security_headers']['weight'] * min(1, len(critical_missing) / 
                                                                                       len(self.risk_weights['missing_security_headers']['headers']))
                    
                    total_risk += score
                    risk_details.append({
                        'category': 'HTTP Headers',
                        'title': 'Missing security headers',
                        'description': 'Critical security headers are missing',
                        'score': score,
                        'max_score': self.risk_weights['missing_security_headers']['weight'],
                        'affected_assets': critical_missing
                    })
        
        return total_risk, risk_details

    def _calculate_technology_risks(self) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Calculate risks related to technology stack.

        Returns:
            Tuple[float, List[Dict[str, Any]]]: Total risk score and risk details.
        """
        total_risk = 0
        risk_details = []
        
        # Check if technology data exists
        if 'tech_stack' in self.recon_data and self.recon_data['tech_stack']:
            tech_stack = self.recon_data['tech_stack']
            
            # Define potentially vulnerable technologies
            vulnerable_cms = ['wordpress', 'joomla', 'drupal', 'magento']
            vulnerable_tech = ['php', 'apache', 'iis', 'nginx']
            
            # Check for outdated CMS
            cms_found = [tech for tech in tech_stack if tech.lower() in vulnerable_cms]
            if cms_found:
                score = self.risk_weights['outdated_cms']['weight'] * min(1, len(cms_found) / 2)
                
                total_risk += score
                risk_details.append({
                    'category': 'Technology',
                    'title': 'CMS detected',
                    'description': 'Content Management Systems may contain vulnerabilities if not updated',
                    'score': score,
                    'max_score': self.risk_weights['outdated_cms']['weight'],
                    'affected_assets': cms_found
                })
            
            # Check for potentially vulnerable technologies
            tech_found = [tech for tech in tech_stack if tech.lower() in vulnerable_tech]
            if tech_found:
                score = self.risk_weights['vulnerable_tech']['weight'] * min(1, len(tech_found) / 3)
                
                total_risk += score
                risk_details.append({
                    'category': 'Technology',
                    'title': 'Potentially vulnerable technologies',
                    'description': 'Technologies that may contain vulnerabilities if not updated',
                    'score': score,
                    'max_score': self.risk_weights['vulnerable_tech']['weight'],
                    'affected_assets': tech_found
                })
        
        return total_risk, risk_details

    def _calculate_path_risks(self) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Calculate risks related to sensitive paths.

        Returns:
            Tuple[float, List[Dict[str, Any]]]: Total risk score and risk details.
        """
        total_risk = 0
        risk_details = []
        
        # Check if sensitive path data exists
        if 'sensitive_paths' in self.recon_data and self.recon_data['sensitive_paths']:
            sensitive_paths = self.recon_data['sensitive_paths']
            path_count = len(sensitive_paths)
            
            # Risk based on number of sensitive paths
            if path_count > self.risk_weights['sensitive_paths']['threshold']:
                score = min(self.risk_weights['sensitive_paths']['weight'] * 
                           (path_count / self.risk_weights['sensitive_paths']['threshold']), 
                           self.risk_weights['sensitive_paths']['weight'] * 2)
                
                total_risk += score
                risk_details.append({
                    'category': 'Sensitive Paths',
                    'title': 'Multiple sensitive paths exposed',
                    'description': f'Found {path_count} sensitive paths or directories',
                    'score': score,
                    'max_score': self.risk_weights['sensitive_paths']['weight'] * 2,
                    'affected_assets': [path.get('path', 'unknown') for path in sensitive_paths[:10]]
                })
            
            # Risk based on highly sensitive paths
            high_sensitivity_paths = []
            for path_info in sensitive_paths:
                if isinstance(path_info, dict) and 'sensitivity' in path_info and path_info['sensitivity'] == 'high':
                    high_sensitivity_paths.append(path_info.get('path', 'unknown'))
            
            if high_sensitivity_paths:
                score = self.risk_weights['high_sensitivity_paths']['weight'] * min(1, len(high_sensitivity_paths) / 3)
                
                total_risk += score
                risk_details.append({
                    'category': 'Sensitive Paths',
                    'title': 'Highly sensitive paths exposed',
                    'description': 'Paths with high sensitivity are accessible',
                    'score': score,
                    'max_score': self.risk_weights['high_sensitivity_paths']['weight'],
                    'affected_assets': high_sensitivity_paths
                })
        
        return total_risk, risk_details

    def _calculate_osint_risks(self) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Calculate risks related to OSINT and breach findings.

        Returns:
            Tuple[float, List[Dict[str, Any]]]: Total risk score and risk details.
        """
        total_risk = 0
        risk_details = []
        
        # Check if OSINT data exists
        if 'osint_findings' in self.recon_data and self.recon_data['osint_findings']:
            osint_data = self.recon_data['osint_findings']
            
            # Check for breaches
            if 'breaches' in osint_data and osint_data['breaches']:
                breaches = osint_data['breaches']
                breach_count = len(breaches)
                
                if breach_count > self.risk_weights['breach_count']['threshold']:
                    score = min(self.risk_weights['breach_count']['weight'] * 
                               (breach_count / (self.risk_weights['breach_count']['threshold'] * 2)), 
                               self.risk_weights['breach_count']['weight'] * 2)
                    
                    total_risk += score
                    risk_details.append({
                        'category': 'OSINT',
                        'title': 'Data breaches detected',
                        'description': f'Found {breach_count} data breaches involving the domain or associated emails',
                        'score': score,
                        'max_score': self.risk_weights['breach_count']['weight'] * 2,
                        'affected_assets': [breach.get('title', 'Unknown breach') for breach in breaches[:5]]
                    })
                
                # Check for credential leaks
                credential_breaches = []
                for breach in breaches:
                    if isinstance(breach, dict) and 'data_classes' in breach:
                        if any(cred in breach['data_classes'] for cred in ['Passwords', 'Credentials']):
                            credential_breaches.append(breach.get('title', 'Unknown breach'))
                
                if credential_breaches:
                    score = self.risk_weights['credential_leak']['weight'] * min(1, len(credential_breaches) / 2)
                    
                    total_risk += score
                    risk_details.append({
                        'category': 'OSINT',
                        'title': 'Credential leaks detected',
                        'description': 'Credentials have been exposed in data breaches',
                        'score': score,
                        'max_score': self.risk_weights['credential_leak']['weight'],
                        'affected_assets': credential_breaches
                    })
        
        return total_risk, risk_details

    def _get_risk_level(self, score: int) -> str:
        """
        Get the risk level based on the score.

        Args:
            score (int): The risk score.

        Returns:
            str: The risk level (Critical, High, Medium, Low, or Informational).
        """
        if score >= 85:
            return "Critical"
        elif score >= 70:
            return "High"
        elif score >= 50:
            return "Medium"
        elif score >= 25:
            return "Low"
        else:
            return "Informational"


def calculate_risk_score(domain: str, recon_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function to calculate risk score.

    Args:
        domain (str): The target domain.
        recon_data (Dict[str, Any]): Reconnaissance data for the domain.

    Returns:
        Dict[str, Any]: A dictionary containing the risk score and details.
    """
    scorer = RiskScorer(domain, recon_data)
    return scorer.calculate_risk_score()


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 2:
        target_domain = sys.argv[1]
        recon_file = sys.argv[2]
        
        try:
            with open(recon_file, 'r') as f:
                recon_data = json.load(f)
            
            result = calculate_risk_score(target_domain, recon_data)
            print(f"\nRisk score for {target_domain}: {result['risk_score']}/100 ({result['risk_level']})")
            
            if result['risk_details']:
                print("\nTop risks:")
                for risk in result['risk_details'][:5]:  # Show top 5
                    print(f"  {risk['title']} ({risk['category']}) - Score: {risk['score']}")
                    print(f"    {risk['description']}")
                    print(f"    Affected: {', '.join(risk['affected_assets'][:3])}")
                    if len(risk['affected_assets']) > 3:
                        print(f"    ... and {len(risk['affected_assets']) - 3} more")
                
                if len(result['risk_details']) > 5:
                    print(f"  ... and {len(result['risk_details']) - 5} more risks")
        
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    else:
        print("Usage: python risk_scorer.py <domain> <recon_data_file>", file=sys.stderr)
