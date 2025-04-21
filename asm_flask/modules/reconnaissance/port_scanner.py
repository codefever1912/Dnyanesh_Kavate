#!/usr/bin/env python3
"""
Port Scanning Module for Attack Surface Monitoring Tool
This module performs port scanning to detect open ports and services.
"""

import nmap
import socket
import sys
import json
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


class PortScanner:
    """
    A class to perform port scanning on target hosts.
    """

    def __init__(self, target: str, ports: str = "1-1000", scan_type: str = "SV", 
                 timing_template: int = 4, max_threads: int = 5):
        """
        Initialize the PortScanner with the target host.

        Args:
            target (str): The target host to scan (domain or IP).
            ports (str): Ports to scan (e.g., "22,80,443" or "1-1000").
            scan_type (str): Scan type (e.g., "SV" for service/version detection).
            timing_template (int): Timing template (0-5, higher is faster but noisier).
            max_threads (int): Maximum number of threads for concurrent operations.
        """
        self.target = target
        self.ports = ports
        self.scan_type = scan_type
        self.timing_template = timing_template
        self.max_threads = max_threads
        self.nm = nmap.PortScanner()
        self.results = {}

    def scan(self) -> Dict[str, Any]:
        """
        Perform port scanning on the target.

        Returns:
            Dict[str, Any]: A dictionary containing scan results.
        """
        print(f"[+] Starting port scan on {self.target} (ports: {self.ports})")
        
        try:
            # Resolve IP address if target is a domain
            ip = self._resolve_ip(self.target)
            if not ip:
                print(f"[!] Could not resolve IP for {self.target}", file=sys.stderr)
                return {"error": f"Could not resolve IP for {self.target}"}
            
            # Construct scan arguments
            args = f"-p{self.ports} -T{self.timing_template}"
            
            if "S" in self.scan_type:
                args += " -sS"  # SYN scan
            if "V" in self.scan_type:
                args += " -sV"  # Version detection
            if "A" in self.scan_type:
                args += " -A"   # OS detection, version detection, script scanning, and traceroute
            
            print(f"[+] Running nmap with args: {args}")
            
            # Run the scan
            self.nm.scan(ip, arguments=args)
            
            # Process results
            if ip in self.nm.all_hosts():
                host_data = self.nm[ip]
                
                # Initialize result structure
                scan_result = {
                    "target": self.target,
                    "ip": ip,
                    "status": host_data.get("status", {}).get("state", "unknown"),
                    "open_ports": [],
                    "os_detection": host_data.get("osmatch", []),
                }
                
                # Process open ports and services
                if "tcp" in host_data:
                    for port, port_data in host_data["tcp"].items():
                        if port_data["state"] == "open":
                            service_info = {
                                "port": port,
                                "protocol": "tcp",
                                "service": port_data.get("name", "unknown"),
                                "product": port_data.get("product", ""),
                                "version": port_data.get("version", ""),
                                "extrainfo": port_data.get("extrainfo", ""),
                                "cpe": port_data.get("cpe", ""),
                            }
                            scan_result["open_ports"].append(service_info)
                            print(f"[+] Found open port {port}/tcp: {service_info['service']} {service_info['product']} {service_info['version']}")
                
                # Process UDP ports if scanned
                if "udp" in host_data:
                    for port, port_data in host_data["udp"].items():
                        if port_data["state"] == "open":
                            service_info = {
                                "port": port,
                                "protocol": "udp",
                                "service": port_data.get("name", "unknown"),
                                "product": port_data.get("product", ""),
                                "version": port_data.get("version", ""),
                                "extrainfo": port_data.get("extrainfo", ""),
                                "cpe": port_data.get("cpe", ""),
                            }
                            scan_result["open_ports"].append(service_info)
                            print(f"[+] Found open port {port}/udp: {service_info['service']} {service_info['product']} {service_info['version']}")
                
                self.results = scan_result
                return scan_result
            else:
                print(f"[!] No hosts found or target is not responding", file=sys.stderr)
                return {"error": "No hosts found or target is not responding"}
        
        except Exception as e:
            print(f"[!] Error during port scanning: {e}", file=sys.stderr)
            return {"error": str(e)}

    def scan_common_ports(self) -> Dict[str, Any]:
        """
        Perform a quick scan of common ports using socket connections.
        Useful as a fallback when nmap is not available or as a quick initial scan.

        Returns:
            Dict[str, Any]: A dictionary containing scan results.
        """
        print(f"[+] Starting quick socket scan on {self.target}")
        
        # Common ports to check
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443
        ]
        
        try:
            # Resolve IP address if target is a domain
            ip = self._resolve_ip(self.target)
            if not ip:
                print(f"[!] Could not resolve IP for {self.target}", file=sys.stderr)
                return {"error": f"Could not resolve IP for {self.target}"}
            
            open_ports = []
            
            # Use ThreadPoolExecutor for parallel scanning
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_port = {executor.submit(self._check_port, ip, port): port for port in common_ports}
                
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        is_open, service = future.result()
                        if is_open:
                            port_info = {
                                "port": port,
                                "protocol": "tcp",
                                "service": service,
                                "product": "",
                                "version": "",
                                "extrainfo": "detected by socket scan",
                                "cpe": "",
                            }
                            open_ports.append(port_info)
                            print(f"[+] Found open port {port}/tcp: {service}")
                    except Exception as e:
                        print(f"[!] Error checking port {port}: {e}", file=sys.stderr)
            
            scan_result = {
                "target": self.target,
                "ip": ip,
                "status": "up" if open_ports else "unknown",
                "open_ports": open_ports,
                "os_detection": [],
            }
            
            self.results = scan_result
            return scan_result
        
        except Exception as e:
            print(f"[!] Error during socket port scanning: {e}", file=sys.stderr)
            return {"error": str(e)}

    def _check_port(self, ip: str, port: int) -> tuple:
        """
        Check if a port is open using a socket connection.

        Args:
            ip (str): IP address to check.
            port (int): Port number to check.

        Returns:
            tuple: (is_open, service_name) where is_open is a boolean and service_name is a string.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        is_open = (result == 0)
        
        service = "unknown"
        if is_open:
            try:
                service = socket.getservbyport(port)
            except:
                # Map common ports to services
                service_map = {
                    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
                    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "microsoft-ds",
                    993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "ms-wbt-server",
                    5900: "vnc", 8080: "http-proxy", 8443: "https-alt"
                }
                service = service_map.get(port, "unknown")
        
        sock.close()
        return (is_open, service)

    def _resolve_ip(self, host: str) -> Optional[str]:
        """
        Resolve a hostname to an IP address.

        Args:
            host (str): Hostname to resolve.

        Returns:
            Optional[str]: IP address if resolved, None otherwise.
        """
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None


def scan_ports(target: str, ports: str = "1-1000") -> Dict[str, Any]:
    """
    Convenience function to perform port scanning on a target.

    Args:
        target (str): The target host to scan (domain or IP).
        ports (str): Ports to scan (e.g., "22,80,443" or "1-1000").

    Returns:
        Dict[str, Any]: A dictionary containing scan results.
    """
    scanner = PortScanner(target, ports)
    try:
        return scanner.scan()
    except Exception as e:
        print(f"[!] Nmap scan failed, falling back to socket scan: {e}", file=sys.stderr)
        return scanner.scan_common_ports()


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 1:
        target_host = sys.argv[1]
        port_range = sys.argv[2] if len(sys.argv) > 2 else "1-1000"
        
        try:
            result = scan_ports(target_host, port_range)
            print(f"\nPort scan results for {target_host}:")
            print(json.dumps(result, indent=2))
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    else:
        print("Usage: python port_scanner.py <target> [port_range]", file=sys.stderr)
