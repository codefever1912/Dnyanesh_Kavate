#!/usr/bin/env python3
"""
Test module for the output components of the Attack Surface Monitoring Tool.
"""

import os
import sys
import unittest
import json
import tempfile
from unittest.mock import patch, MagicMock

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.output.json_formatter import generate_json_report
from modules.output.markdown_exporter import generate_markdown_report
from modules.output.html_exporter import generate_html_report


class TestOutputModule(unittest.TestCase):
    """Test cases for the output module."""

    def setUp(self):
        """Set up test data."""
        # Sample reconnaissance data
        self.recon_data = {
            "subdomains": ["sub1.example.com", "sub2.example.com"],
            "dns_records": {
                "A": ["192.0.2.1"],
                "MX": ["mail.example.com"]
            },
            "open_ports": [
                {"port": 80, "service": "http", "product": "Apache", "version": "2.4.41"},
                {"port": 443, "service": "https"}
            ],
            "tech_stack": ["Apache", "PHP", "jQuery"],
            "headers": {
                "Server": "Apache",
                "X-Content-Type-Options": "nosniff"
            },
            "ssl_info": {
                "grade": "B",
                "certificate": {
                    "subject": {"common_name": "example.com"},
                    "issuer": {"common_name": "Let's Encrypt"},
                    "not_before": "2023-01-01",
                    "not_after": "2024-01-01",
                    "expired": False,
                    "self_signed": False
                },
                "protocols": {
                    "TLSv1.2": True,
                    "TLSv1.3": True,
                    "SSLv3": False
                },
                "vulnerabilities": []
            },
            "sensitive_paths": [
                {"path": "/admin", "status_code": 302, "sensitivity": "high"},
                {"path": "/config", "status_code": 403, "sensitivity": "high"}
            ],
            "osint_findings": {
                "breach_count": 1,
                "emails_found": ["user@example.com"],
                "breaches": [
                    {
                        "title": "Example Breach",
                        "breach_date": "2020-01-01",
                        "data_classes": ["Emails", "Passwords"]
                    }
                ]
            }
        }
        
        # Sample risk data
        self.risk_data = {
            "domain": "example.com",
            "risk_score": 65,
            "risk_level": "Medium",
            "risk_details": [
                {
                    "category": "Port",
                    "title": "Critical services exposed",
                    "description": "Critical services are exposed to the internet",
                    "score": 15,
                    "severity": "High",
                    "affected_assets": ["22 (ssh)", "3389 (rdp)"]
                },
                {
                    "category": "HTTP Headers",
                    "title": "Missing security headers",
                    "description": "Critical security headers are missing",
                    "score": 10,
                    "severity": "Medium",
                    "affected_assets": ["Content-Security-Policy", "X-Frame-Options"]
                }
            ]
        }
        
        # Sample AI analysis
        self.ai_analysis = {
            "summary": "The domain has a moderate risk profile with several security issues that should be addressed.",
            "key_risks": [
                "Critical services exposed to the internet",
                "Missing security headers",
                "Sensitive paths exposed"
            ],
            "recommendations": [
                "Restrict access to critical services",
                "Implement all recommended security headers",
                "Secure or remove sensitive paths"
            ]
        }

    def test_json_formatter(self):
        """Test JSON report generation."""
        # Create a temporary file for the JSON report
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            temp_file_name = temp_file.name
        
        try:
            # Generate JSON report
            report = generate_json_report(
                "example.com",
                self.recon_data,
                self.risk_data,
                self.ai_analysis,
                temp_file_name
            )
            
            # Verify the report was generated
            self.assertTrue(os.path.exists(temp_file_name))
            
            # Verify the report contains valid JSON
            with open(temp_file_name, 'r') as f:
                report_data = json.load(f)
            
            # Verify the report structure
            self.assertEqual(report_data["domain"], "example.com")
            self.assertEqual(report_data["risk_score"], 65)
            self.assertEqual(report_data["risk_summary"], self.ai_analysis["summary"])
            self.assertIn("subdomains", report_data)
            self.assertIn("dns_records", report_data)
            self.assertIn("open_ports", report_data)
            self.assertIn("tech_stack", report_data)
            self.assertIn("headers", report_data)
            self.assertIn("ssl_info", report_data)
            self.assertIn("osint_findings", report_data)
            self.assertIn("sensitive_paths", report_data)
            self.assertIn("risk_details", report_data)
            self.assertIn("recommendations", report_data)
        
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_file_name):
                os.unlink(temp_file_name)

    def test_markdown_exporter(self):
        """Test Markdown report generation."""
        # First generate a JSON report
        json_report = generate_json_report(
            "example.com",
            self.recon_data,
            self.risk_data,
            self.ai_analysis
        )
        
        # Create a temporary file for the Markdown report
        with tempfile.NamedTemporaryFile(suffix='.md', delete=False) as temp_file:
            temp_file_name = temp_file.name
        
        try:
            # Generate Markdown report
            markdown = generate_markdown_report(json_report, temp_file_name)
            
            # Verify the report was generated
            self.assertTrue(os.path.exists(temp_file_name))
            
            # Verify the report content
            with open(temp_file_name, 'r') as f:
                content = f.read()
            
            # Check for key sections in the Markdown
            self.assertIn("# Attack Surface Monitoring Report: example.com", content)
            self.assertIn("## Executive Summary", content)
            self.assertIn("## Key Recommendations", content)
            self.assertIn("## Subdomains", content)
            self.assertIn("## DNS Records", content)
            self.assertIn("## Open Ports and Services", content)
            self.assertIn("## Technology Stack", content)
            self.assertIn("## HTTP Headers", content)
            self.assertIn("## SSL/TLS Configuration", content)
            self.assertIn("## Sensitive Paths", content)
            self.assertIn("## OSINT and Breach Findings", content)
            self.assertIn("## Detailed Risk Findings", content)
        
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_file_name):
                os.unlink(temp_file_name)

    def test_html_exporter(self):
        """Test HTML report generation."""
        # First generate a JSON report
        json_report = generate_json_report(
            "example.com",
            self.recon_data,
            self.risk_data,
            self.ai_analysis
        )
        
        # Create a temporary file for the HTML report
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as temp_file:
            temp_file_name = temp_file.name
        
        try:
            # Generate HTML report
            html = generate_html_report(json_report, temp_file_name)
            
            # Verify the report was generated
            self.assertTrue(os.path.exists(temp_file_name))
            
            # Verify the report content
            with open(temp_file_name, 'r') as f:
                content = f.read()
            
            # Check for key elements in the HTML
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("<title>ASM Report: example.com</title>", content)
            self.assertIn("<h1>Attack Surface Monitoring Report: example.com</h1>", content)
            self.assertIn("Executive Summary", content)
            self.assertIn("Key Recommendations", content)
            self.assertIn("Subdomains", content)
            self.assertIn("Open Ports and Services", content)
            self.assertIn("Technology Stack", content)
            self.assertIn("HTTP Headers", content)
            self.assertIn("SSL/TLS Configuration", content)
            self.assertIn("Sensitive Paths", content)
            self.assertIn("OSINT and Breach Findings", content)
            self.assertIn("Risk Details", content)
            
            # Check for CSS styles
            self.assertIn("<style>", content)
            self.assertIn("</style>", content)
            
            # Check for JavaScript
            self.assertIn("<script>", content)
            self.assertIn("</script>", content)
        
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_file_name):
                os.unlink(temp_file_name)


if __name__ == '__main__':
    unittest.main()
