#!/usr/bin/env python3
"""
Test module for the reconnaissance components of the Attack Surface Monitoring Tool.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.reconnaissance.subdomain_enum import enumerate_subdomains
from modules.reconnaissance.live_subdomain import check_live_subdomains
from modules.reconnaissance.whois_dns import analyze_domain
from modules.reconnaissance.port_scanner import scan_ports
from modules.reconnaissance.service_fingerprint import fingerprint_services
from modules.reconnaissance.tech_detector import detect_technologies
from modules.reconnaissance.ssl_analyzer import analyze_ssl
from modules.reconnaissance.header_security import audit_headers
from modules.reconnaissance.path_discovery import discover_paths
from modules.reconnaissance.osint_breach import check_breaches


class TestReconnaissanceModule(unittest.TestCase):
    """Test cases for the reconnaissance module."""

    @patch('modules.reconnaissance.subdomain_enum.dns.resolver.resolve')
    @patch('modules.reconnaissance.subdomain_enum.requests.get')
    def test_subdomain_enumeration(self, mock_get, mock_resolve):
        """Test subdomain enumeration functionality."""
        # Mock DNS resolution
        mock_resolve.return_value = MagicMock()
        
        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "subdomain1.example.com\nsubdomain2.example.com"
        mock_get.return_value = mock_response
        
        # Test subdomain enumeration
        subdomains = enumerate_subdomains("example.com")
        
        # Verify results
        self.assertIsInstance(subdomains, list)
        self.assertGreaterEqual(len(subdomains), 2)  # At least the mocked subdomains

    @patch('modules.reconnaissance.live_subdomain.requests.get')
    def test_live_subdomain_detection(self, mock_get):
        """Test live subdomain detection functionality."""
        # Mock HTTP responses
        mock_response_live = MagicMock()
        mock_response_live.status_code = 200
        
        mock_response_down = MagicMock()
        mock_response_down.status_code = 404
        
        # Configure mock to return different responses for different URLs
        def mock_get_response(url, *args, **kwargs):
            if "live" in url:
                return mock_response_live
            else:
                return mock_response_down
        
        mock_get.side_effect = mock_get_response
        
        # Test live subdomain detection
        subdomains = ["live.example.com", "down.example.com"]
        live_subdomains = check_live_subdomains(subdomains)
        
        # Verify results
        self.assertIsInstance(live_subdomains, list)
        self.assertEqual(len(live_subdomains), 1)  # Only the "live" subdomain should be detected

    @patch('modules.reconnaissance.whois_dns.whois.whois')
    @patch('modules.reconnaissance.whois_dns.dns.resolver.resolve')
    def test_whois_dns_analysis(self, mock_resolve, mock_whois):
        """Test WHOIS and DNS records analysis functionality."""
        # Mock WHOIS response
        mock_whois.return_value = {
            'domain_name': 'EXAMPLE.COM',
            'registrar': 'Example Registrar',
            'creation_date': '2000-01-01',
            'expiration_date': '2030-01-01'
        }
        
        # Mock DNS resolution
        mock_resolve.return_value = MagicMock()
        mock_resolve.return_value.response = MagicMock()
        
        # Test WHOIS and DNS analysis
        results = analyze_domain("example.com")
        
        # Verify results
        self.assertIsInstance(results, dict)
        self.assertIn('whois', results)
        self.assertIn('dns_records', results)
        self.assertIn('domain_name', results['whois'])

    @patch('modules.reconnaissance.port_scanner.nmap.PortScanner')
    def test_port_scanning(self, mock_port_scanner):
        """Test port scanning functionality."""
        # Mock nmap scanner
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {
            'scan': {
                'example.com': {
                    'tcp': {
                        80: {'state': 'open', 'name': 'http'},
                        443: {'state': 'open', 'name': 'https'}
                    }
                }
            }
        }
        mock_port_scanner.return_value = mock_scanner
        
        # Test port scanning
        results = scan_ports("example.com")
        
        # Verify results
        self.assertIsInstance(results, dict)
        self.assertIn('open_ports', results)
        self.assertEqual(len(results['open_ports']), 2)  # Two open ports (80, 443)

    @patch('modules.reconnaissance.service_fingerprint.nmap.PortScanner')
    def test_service_fingerprinting(self, mock_port_scanner):
        """Test service fingerprinting functionality."""
        # Mock nmap scanner
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {
            'scan': {
                'example.com': {
                    'tcp': {
                        80: {
                            'state': 'open',
                            'name': 'http',
                            'product': 'Apache',
                            'version': '2.4.41'
                        }
                    }
                }
            }
        }
        mock_port_scanner.return_value = mock_scanner
        
        # Test service fingerprinting
        open_ports = [{'port': 80, 'service': 'http'}]
        results = fingerprint_services("example.com", open_ports)
        
        # Verify results
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 1)
        self.assertIn('product', results[0])
        self.assertIn('version', results[0])

    @patch('modules.reconnaissance.tech_detector.requests.get')
    def test_technology_detection(self, mock_get):
        """Test technology stack detection functionality."""
        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><head><script src='jquery.js'></script></head><body></body></html>"
        mock_get.return_value = mock_response
        
        # Test technology detection
        results = detect_technologies("example.com")
        
        # Verify results
        self.assertIsInstance(results, dict)
        self.assertIn('technologies', results)
        self.assertIsInstance(results['technologies'], list)

    @patch('modules.reconnaissance.ssl_analyzer.socket.create_connection')
    @patch('modules.reconnaissance.ssl_analyzer.ssl.create_default_context')
    def test_ssl_analysis(self, mock_ssl_context, mock_socket):
        """Test SSL/TLS analysis functionality."""
        # Mock SSL context and socket
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = MagicMock()
        mock_ssl_context.return_value = mock_context
        
        mock_socket.return_value = MagicMock()
        
        # Test SSL analysis
        results = analyze_ssl("example.com")
        
        # Verify results
        self.assertIsInstance(results, dict)
        self.assertIn('certificate', results)
        self.assertIn('protocols', results)

    @patch('modules.reconnaissance.header_security.requests.get')
    def test_header_security_audit(self, mock_get):
        """Test HTTP header security audit functionality."""
        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Server': 'Apache',
            'Content-Type': 'text/html',
            'X-Content-Type-Options': 'nosniff'
        }
        mock_get.return_value = mock_response
        
        # Test header security audit
        results = audit_headers("example.com")
        
        # Verify results
        self.assertIsInstance(results, dict)
        self.assertIn('headers', results)
        self.assertIn('missing_headers', results)
        self.assertIn('grade', results)

    @patch('modules.reconnaissance.path_discovery.requests.get')
    def test_sensitive_path_discovery(self, mock_get):
        """Test sensitive path discovery functionality."""
        # Mock HTTP responses
        def mock_get_response(url, *args, **kwargs):
            response = MagicMock()
            if "admin" in url:
                response.status_code = 200
            elif "config" in url:
                response.status_code = 403
            else:
                response.status_code = 404
            return response
        
        mock_get.side_effect = mock_get_response
        
        # Test sensitive path discovery
        results = discover_paths("example.com", "small")
        
        # Verify results
        self.assertIsInstance(results, dict)
        self.assertIn('discovered_paths', results)
        self.assertIsInstance(results['discovered_paths'], list)

    @patch('modules.reconnaissance.osint_breach.requests.get')
    def test_osint_breach_check(self, mock_get):
        """Test OSINT and breach check functionality."""
        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "Name": "Example Breach",
                "Title": "Example Breach",
                "Domain": "example.com",
                "BreachDate": "2020-01-01",
                "DataClasses": ["Emails", "Passwords"]
            }
        ]
        mock_get.return_value = mock_response
        
        # Test OSINT and breach check
        results = check_breaches("example.com")
        
        # Verify results
        self.assertIsInstance(results, dict)
        self.assertIn('breach_count', results)
        self.assertIn('breaches', results)
        self.assertIn('emails_found', results)


if __name__ == '__main__':
    unittest.main()
