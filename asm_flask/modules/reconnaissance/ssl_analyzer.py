#!/usr/bin/env python3
"""
SSL/TLS Analysis Module for Attack Surface Monitoring Tool
This module analyzes SSL/TLS configurations of web servers.
"""

import socket
import ssl
import sys
import json
import datetime
from typing import Dict, Any, List, Optional, Tuple


class SSLAnalyzer:
    """
    A class to analyze SSL/TLS configurations of web servers.
    """

    def __init__(self, target: str, port: int = 443, timeout: int = 10):
        """
        Initialize the SSLAnalyzer with the target host.

        Args:
            target (str): The target host to analyze (domain or IP).
            port (int): Port to connect to (default: 443).
            timeout (int): Timeout in seconds for connections.
        """
        self.target = target
        self.port = port
        self.timeout = timeout
        
        # Define weak ciphers and protocols
        self.weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
        self.weak_ciphers = [
            'NULL', 'EXPORT', 'DES', '3DES', 'RC4', 'MD5', 'SHA1', 'ANON',
            'ADH', 'AECDH', 'DHE-DSS-DES-CBC3-SHA', 'DHE-RSA-DES-CBC3-SHA'
        ]

    def analyze(self) -> Dict[str, Any]:
        """
        Analyze SSL/TLS configuration.

        Returns:
            Dict[str, Any]: A dictionary containing SSL/TLS analysis results.
        """
        print(f"[+] Analyzing SSL/TLS configuration for {self.target}:{self.port}")
        
        result = {
            "target": self.target,
            "port": self.port,
            "has_ssl": False,
            "certificate": {},
            "protocols": {},
            "cipher_suites": [],
            "vulnerabilities": [],
            "grade": "F",
            "issues": []
        }
        
        try:
            # Check if SSL/TLS is available
            if not self._check_ssl_available():
                result["issues"].append("No SSL/TLS service detected")
                return result
            
            result["has_ssl"] = True
            
            # Get certificate information
            cert_info = self._get_certificate_info()
            result["certificate"] = cert_info
            
            # Check certificate validity
            if cert_info.get("expired", True):
                result["vulnerabilities"].append("expired_certificate")
                result["issues"].append("Certificate has expired")
            
            if cert_info.get("self_signed", True):
                result["vulnerabilities"].append("self_signed_certificate")
                result["issues"].append("Self-signed certificate detected")
            
            # Check supported protocols
            protocols = self._check_protocols()
            result["protocols"] = protocols
            
            for protocol in self.weak_protocols:
                if protocols.get(protocol, False):
                    result["vulnerabilities"].append(f"supports_{protocol.lower()}")
                    result["issues"].append(f"Supports weak protocol: {protocol}")
            
            # Check cipher suites
            ciphers = self._check_cipher_suites()
            result["cipher_suites"] = ciphers
            
            weak_ciphers_found = []
            for cipher in ciphers:
                for weak in self.weak_ciphers:
                    if weak in cipher:
                        weak_ciphers_found.append(cipher)
                        break
            
            if weak_ciphers_found:
                result["vulnerabilities"].append("weak_cipher_suites")
                result["issues"].append(f"Supports weak cipher suites: {', '.join(weak_ciphers_found[:3])}")
                if len(weak_ciphers_found) > 3:
                    result["issues"][-1] += f" and {len(weak_ciphers_found) - 3} more"
            
            # Calculate grade based on vulnerabilities
            result["grade"] = self._calculate_grade(result["vulnerabilities"])
            
            print(f"[+] SSL/TLS analysis complete: Grade {result['grade']}, {len(result['vulnerabilities'])} vulnerabilities found")
            
            return result
        
        except Exception as e:
            print(f"[!] Error analyzing SSL/TLS: {e}", file=sys.stderr)
            result["issues"].append(f"Error during analysis: {str(e)}")
            return result

    def _check_ssl_available(self) -> bool:
        """
        Check if SSL/TLS is available on the target.

        Returns:
            bool: True if SSL/TLS is available, False otherwise.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.close()
            return True
        except:
            return False

    def _get_certificate_info(self) -> Dict[str, Any]:
        """
        Get certificate information.

        Returns:
            Dict[str, Any]: A dictionary containing certificate information.
        """
        cert_info = {
            "subject": {},
            "issuer": {},
            "version": None,
            "serial_number": None,
            "not_before": None,
            "not_after": None,
            "expired": True,
            "self_signed": True,
            "signature_algorithm": None,
            "public_key_algorithm": None,
            "key_size": None,
            "san": []
        }
        
        try:
            # Create an SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect to the server
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    # Get the certificate
                    cert = ssock.getpeercert(True)
                    x509 = ssl.DER_cert_to_PEM_cert(cert)
                    
                    # Get certificate details using OpenSSL
                    cert_dict = ssock.getpeercert()
                    
                    # Extract subject
                    if 'subject' in cert_dict:
                        for item in cert_dict['subject']:
                            for key, value in item:
                                if key == 'commonName':
                                    cert_info['subject']['common_name'] = value
                                elif key == 'organizationName':
                                    cert_info['subject']['organization'] = value
                                elif key == 'organizationalUnitName':
                                    cert_info['subject']['organizational_unit'] = value
                                elif key == 'countryName':
                                    cert_info['subject']['country'] = value
                    
                    # Extract issuer
                    if 'issuer' in cert_dict:
                        for item in cert_dict['issuer']:
                            for key, value in item:
                                if key == 'commonName':
                                    cert_info['issuer']['common_name'] = value
                                elif key == 'organizationName':
                                    cert_info['issuer']['organization'] = value
                                elif key == 'organizationalUnitName':
                                    cert_info['issuer']['organizational_unit'] = value
                                elif key == 'countryName':
                                    cert_info['issuer']['country'] = value
                    
                    # Check if self-signed
                    cert_info['self_signed'] = (
                        cert_info['subject'].get('common_name') == cert_info['issuer'].get('common_name') and
                        cert_info['subject'].get('organization') == cert_info['issuer'].get('organization')
                    )
                    
                    # Extract validity dates
                    if 'notBefore' in cert_dict:
                        cert_info['not_before'] = cert_dict['notBefore']
                    if 'notAfter' in cert_dict:
                        cert_info['not_after'] = cert_dict['notAfter']
                    
                    # Check if expired
                    if 'notAfter' in cert_dict:
                        not_after = ssl.cert_time_to_seconds(cert_dict['notAfter'])
                        now = datetime.datetime.now().timestamp()
                        cert_info['expired'] = now > not_after
                    
                    # Extract SAN
                    if 'subjectAltName' in cert_dict:
                        for type_name, value in cert_dict['subjectAltName']:
                            if type_name == 'DNS':
                                cert_info['san'].append(value)
                    
                    # Extract version and signature algorithm
                    cert_info['version'] = cert_dict.get('version')
                    cert_info['signature_algorithm'] = ssock.context.get_ciphers()[0]['name']
                    
                    # Estimate key size from signature algorithm
                    if 'RSA' in cert_info['signature_algorithm']:
                        cert_info['public_key_algorithm'] = 'RSA'
                        if 'WITH_AES_256' in cert_info['signature_algorithm']:
                            cert_info['key_size'] = 2048
                        else:
                            cert_info['key_size'] = 1024
                    elif 'ECDSA' in cert_info['signature_algorithm']:
                        cert_info['public_key_algorithm'] = 'ECDSA'
                        cert_info['key_size'] = 256
            
            return cert_info
        
        except Exception as e:
            print(f"[!] Error getting certificate info: {e}", file=sys.stderr)
            return cert_info

    def _check_protocols(self) -> Dict[str, bool]:
        """
        Check which SSL/TLS protocols are supported.

        Returns:
            Dict[str, bool]: A dictionary mapping protocol names to support status.
        """
        protocols = {
            'SSLv2': False,
            'SSLv3': False,
            'TLSv1': False,
            'TLSv1.1': False,
            'TLSv1.2': False,
            'TLSv1.3': False
        }
        
        # SSLv2 (very old, should be disabled)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.options &= ~ssl.OP_NO_SSLv2
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock) as ssock:
                    if ssock.version() == 'SSLv2':
                        protocols['SSLv2'] = True
        except:
            pass
        
        # SSLv3 (old, should be disabled)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.options &= ~ssl.OP_NO_SSLv3
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock) as ssock:
                    if ssock.version() == 'SSLv3':
                        protocols['SSLv3'] = True
        except:
            pass
        
        # TLSv1 (old, should be upgraded)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock) as ssock:
                    if ssock.version() == 'TLSv1':
                        protocols['TLSv1'] = True
        except:
            pass
        
        # TLSv1.1 (older, should be upgraded)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock) as ssock:
                    if ssock.version() == 'TLSv1.1':
                        protocols['TLSv1.1'] = True
        except:
            pass
        
        # TLSv1.2 (good)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock) as ssock:
                    if ssock.version() == 'TLSv1.2':
                        protocols['TLSv1.2'] = True
        except:
            pass
        
        # TLSv1.3 (best)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock) as ssock:
                    if ssock.version() == 'TLSv1.3':
                        protocols['TLSv1.3'] = True
        except:
            pass
        
        return protocols

    def _check_cipher_suites(self) -> List[str]:
        """
        Check which cipher suites are supported.

        Returns:
            List[str]: A list of supported cipher suites.
        """
        ciphers = []
        
        try:
            # Create an SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect to the server
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    # Get the cipher used
                    current_cipher = ssock.cipher()
                    if current_cipher:
                        ciphers.append(current_cipher[0])
            
            # Try to get more ciphers by setting different TLS versions
            for protocol in [ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1, ssl.PROTOCOL_TLSv1_2]:
                try:
                    context = ssl.SSLContext(protocol)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                        with context.wrap_socket(sock) as ssock:
                            current_cipher = ssock.cipher()
                            if current_cipher and current_cipher[0] not in ciphers:
                                ciphers.append(current_cipher[0])
                except:
                    pass
        
        except Exception as e:
            print(f"[!] Error checking cipher suites: {e}", file=sys.stderr)
        
        return ciphers

    def _calculate_grade(self, vulnerabilities: List[str]) -> str:
        """
        Calculate a grade based on vulnerabilities.

        Args:
            vulnerabilities (List[str]): List of vulnerability identifiers.

        Returns:
            str: A grade from A+ to F.
        """
        # Critical vulnerabilities
        if any(v in vulnerabilities for v in ['supports_sslv2', 'supports_sslv3']):
            return 'F'
        
        # Serious vulnerabilities
        if any(v in vulnerabilities for v in ['expired_certificate', 'self_signed_certificate']):
            return 'D'
        
        # Medium vulnerabilities
        if any(v in vulnerabilities for v in ['supports_tlsv1', 'supports_tlsv1.1', 'weak_cipher_suites']):
            return 'C'
        
        # Count total vulnerabilities
        if len(vulnerabilities) > 3:
            return 'C'
        elif len(vulnerabilities) > 0:
            return 'B'
        
        # Check for TLS 1.3 support
        if self._check_protocols().get('TLSv1.3', False):
            return 'A+'
        elif self._check_protocols().get('TLSv1.2', False):
            return 'A'
        
        return 'B'


def analyze_ssl(target: str, port: int = 443) -> Dict[str, Any]:
    """
    Convenience function to analyze SSL/TLS configuration.

    Args:
        target (str): The target host to analyze (domain or IP).
        port (int): Port to connect to (default: 443).

    Returns:
        Dict[str, Any]: A dictionary containing SSL/TLS analysis results.
    """
    analyzer = SSLAnalyzer(target, port)
    return analyzer.analyze()


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 1:
        target_host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
        
        try:
            result = analyze_ssl(target_host, port)
            print(f"\nSSL/TLS analysis results for {target_host}:{port}")
            print(f"Grade: {result['grade']}")
            print(f"Vulnerabilities: {', '.join(result['vulnerabilities']) if result['vulnerabilities'] else 'None'}")
            print(f"Issues: {', '.join(result['issues']) if result['issues'] else 'None'}")
            print(f"Certificate: Expires {result['certificate'].get('not_after', 'Unknown')}")
            print(f"Supported protocols: {', '.join([p for p, supported in result['protocols'].items() if supported])}")
            print(f"Cipher suites: {', '.join(result['cipher_suites'])}")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    else:
        print("Usage: python ssl_analyzer.py <target> [port]", file=sys.stderr)
