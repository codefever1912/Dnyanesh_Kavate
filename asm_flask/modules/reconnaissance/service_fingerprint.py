#!/usr/bin/env python3
"""
Service Fingerprinting Module for Attack Surface Monitoring Tool
This module identifies services and their versions running on open ports.
"""

import socket
import sys
import json
import re
from typing import Dict, Any, List, Optional, Tuple

# Service banners and signatures
SERVICE_SIGNATURES = {
    'ssh': [
        (r'SSH-2.0-(OpenSSH_[\d\.]+)', 'OpenSSH'),
        (r'SSH-2.0-(\w+)', None)
    ],
    'http': [
        (r'Server: ([\w\d\./() -]+)', None),
        (r'X-Powered-By: ([\w\d\./() -]+)', None)
    ],
    'ftp': [
        (r'^220 (.*) FTP', None),
        (r'^220[\s-]+([\w\d\./() -]+)', None)
    ],
    'smtp': [
        (r'^220 (.*) ESMTP', None),
        (r'^220 (.*) SMTP', None)
    ],
    'pop3': [
        (r'\+OK (.*) POP3', None)
    ],
    'imap': [
        (r'\* OK (.*) IMAP', None)
    ],
    'mysql': [
        (r'([0-9]+)\x00\x00\x00\x0a([0-9.]+)', 'MySQL')
    ],
    'redis': [
        (r'-NOAUTH Authentication required', 'Redis'),
        (r'\-ERR operation not permitted', 'Redis')
    ],
    'mongodb': [
        (r'MongoDB Server', 'MongoDB')
    ]
}

# Common service port mappings
COMMON_PORTS = {
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'dns',
    80: 'http',
    110: 'pop3',
    143: 'imap',
    443: 'https',
    445: 'smb',
    993: 'imaps',
    995: 'pop3s',
    3306: 'mysql',
    3389: 'rdp',
    5432: 'postgresql',
    5900: 'vnc',
    6379: 'redis',
    8080: 'http-alt',
    8443: 'https-alt',
    27017: 'mongodb'
}


class ServiceFingerprinter:
    """
    A class to fingerprint services running on open ports.
    """

    def __init__(self, target: str, timeout: int = 5):
        """
        Initialize the ServiceFingerprinter with the target host.

        Args:
            target (str): The target host to fingerprint (domain or IP).
            timeout (int): Timeout in seconds for connections.
        """
        self.target = target
        self.timeout = timeout

    def fingerprint_service(self, port: int, protocol: str = 'tcp') -> Dict[str, Any]:
        """
        Fingerprint a service running on a specific port.

        Args:
            port (int): Port number to fingerprint.
            protocol (str): Protocol to use ('tcp' or 'udp').

        Returns:
            Dict[str, Any]: A dictionary containing service information.
        """
        print(f"[+] Fingerprinting service on {self.target}:{port}/{protocol}")
        
        service_info = {
            "port": port,
            "protocol": protocol,
            "service": COMMON_PORTS.get(port, "unknown"),
            "product": "",
            "version": "",
            "banner": "",
            "confidence": "low"
        }
        
        try:
            # Get banner
            banner = self._get_banner(port)
            
            if banner:
                service_info["banner"] = banner
                service_info["confidence"] = "medium"
                
                # Try to identify service and version from banner
                service_name, product, version = self._identify_from_banner(banner, port)
                
                if service_name:
                    service_info["service"] = service_name
                
                if product:
                    service_info["product"] = product
                    service_info["confidence"] = "high"
                
                if version:
                    service_info["version"] = version
                    service_info["confidence"] = "high"
                
                print(f"[+] Identified: {service_info['service']} {service_info['product']} {service_info['version']}")
        
        except Exception as e:
            print(f"[!] Error fingerprinting service on port {port}: {e}", file=sys.stderr)
        
        return service_info

    def fingerprint_services(self, ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Fingerprint services running on multiple ports.

        Args:
            ports (List[Dict[str, Any]]): List of port dictionaries with port and protocol information.

        Returns:
            List[Dict[str, Any]]: A list of dictionaries containing service information.
        """
        results = []
        
        for port_info in ports:
            port = int(port_info["port"])
            protocol = port_info.get("protocol", "tcp")
            
            # Skip if already has detailed service info
            if port_info.get("product") and port_info.get("version"):
                results.append(port_info)
                continue
            
            # Fingerprint the service
            service_info = self.fingerprint_service(port, protocol)
            
            # Merge with existing info
            merged_info = port_info.copy()
            for key, value in service_info.items():
                if value and (key not in merged_info or not merged_info[key]):
                    merged_info[key] = value
            
            results.append(merged_info)
        
        return results

    def _get_banner(self, port: int) -> str:
        """
        Get service banner by connecting to the port.

        Args:
            port (int): Port number to connect to.

        Returns:
            str: Service banner if available, empty string otherwise.
        """
        banner = ""
        sock = None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            
            # For some protocols, we need to send data to get a response
            if port in [80, 443, 8080, 8443]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 25:
                sock.send(b"EHLO example.com\r\n")
            elif port == 110:
                sock.send(b"USER anonymous\r\n")
            elif port == 21:
                sock.send(b"USER anonymous\r\n")
            
            # Receive data
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
        
        except (socket.timeout, ConnectionRefusedError):
            pass
        except Exception as e:
            print(f"[!] Error getting banner on port {port}: {e}", file=sys.stderr)
        
        finally:
            if sock:
                sock.close()
        
        return banner

    def _identify_from_banner(self, banner: str, port: int) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Identify service, product, and version from a banner.

        Args:
            banner (str): Service banner.
            port (int): Port number.

        Returns:
            Tuple[Optional[str], Optional[str], Optional[str]]: Service name, product, and version.
        """
        service_name = None
        product = None
        version = None
        
        # Try to identify based on common port
        default_service = COMMON_PORTS.get(port)
        
        # Check for service-specific patterns
        if default_service and default_service in SERVICE_SIGNATURES:
            for pattern, prod in SERVICE_SIGNATURES[default_service]:
                match = re.search(pattern, banner, re.IGNORECASE | re.MULTILINE)
                if match:
                    service_name = default_service
                    if prod:
                        product = prod
                    else:
                        product = match.group(1)
                    
                    # Try to extract version
                    version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', product)
                    if version_match:
                        version = version_match.group(1)
                        # Clean up product name
                        product = re.sub(r'\s*' + re.escape(version) + r'\s*', '', product).strip()
                    
                    break
        
        # Check for HTTP server header if not identified yet
        if not service_name and port in [80, 443, 8080, 8443]:
            server_match = re.search(r'Server: ([^\r\n]+)', banner)
            if server_match:
                service_name = "http" if port != 443 else "https"
                product = server_match.group(1).strip()
                
                # Try to extract version
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', product)
                if version_match:
                    version = version_match.group(1)
                    # Clean up product name
                    product = re.sub(r'\s*' + re.escape(version) + r'\s*', '', product).strip()
        
        # If we still don't have a service name, use the default
        if not service_name:
            service_name = default_service
        
        return service_name, product, version


def fingerprint_services(target: str, ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Convenience function to fingerprint services on a target.

    Args:
        target (str): The target host to fingerprint (domain or IP).
        ports (List[Dict[str, Any]]): List of port dictionaries with port and protocol information.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries containing service information.
    """
    fingerprinter = ServiceFingerprinter(target)
    return fingerprinter.fingerprint_services(ports)


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 2:
        target_host = sys.argv[1]
        ports_json = sys.argv[2]
        
        try:
            ports = json.loads(ports_json)
            result = fingerprint_services(target_host, ports)
            print(f"\nService fingerprinting results for {target_host}:")
            print(json.dumps(result, indent=2))
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    else:
        print("Usage: python service_fingerprint.py <target> '<[{\"port\": 80, \"protocol\": \"tcp\"}, ...]>'", file=sys.stderr)
