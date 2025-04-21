#!/usr/bin/env python3
"""
Test module for the risk analysis components of the Attack Surface Monitoring Tool.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.risk_analysis.risk_scorer import calculate_risk_score
from modules.risk_analysis.ai_analyzer import analyze_risks


class TestRiskAnalysisModule(unittest.TestCase):
    """Test cases for the risk analysis module."""

    def test_risk_scoring(self):
        """Test risk scoring functionality."""
        # Sample reconnaissance data
        recon_data = {
            "subdomains": ["sub1.example.com", "sub2.example.com", "sub3.example.com"],
            "open_ports": [
                {"port": 80, "service": "http", "product": "Apache", "version": "2.4.41"},
                {"port": 443, "service": "https"},
                {"port": 22, "service": "ssh"}
            ],
            "ssl_info": {
                "grade": "B",
                "certificate": {
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
            "headers": {
                "headers": {
                    "Server": "Apache",
                    "X-Content-Type-Options": "nosniff"
                },
                "missing_headers": ["Content-Security-Policy", "X-Frame-Options"]
            },
            "tech_stack": ["Apache", "PHP", "jQuery"],
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
        
        # Test risk scoring
        risk_data = calculate_risk_score("example.com", recon_data)
        
        # Verify results
        self.assertIsInstance(risk_data, dict)
        self.assertIn("risk_score", risk_data)
        self.assertIn("risk_level", risk_data)
        self.assertIn("risk_details", risk_data)
        
        # Verify risk score is in valid range
        self.assertGreaterEqual(risk_data["risk_score"], 0)
        self.assertLessEqual(risk_data["risk_score"], 100)
        
        # Verify risk level is valid
        self.assertIn(risk_data["risk_level"], ["Critical", "High", "Medium", "Low", "Informational"])
        
        # Verify risk details
        self.assertIsInstance(risk_data["risk_details"], list)
        if risk_data["risk_details"]:
            first_risk = risk_data["risk_details"][0]
            self.assertIn("category", first_risk)
            self.assertIn("title", first_risk)
            self.assertIn("description", first_risk)
            self.assertIn("score", first_risk)

    @patch('modules.risk_analysis.ai_analyzer.requests.post')
    def test_ai_analysis(self, mock_post):
        """Test AI analysis functionality."""
        # Mock AI response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "summary": "This is a test summary of the security posture.",
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
        mock_post.return_value = mock_response
        
        # Sample risk data
        risk_data = {
            "domain": "example.com",
            "risk_score": 65,
            "risk_level": "Medium",
            "risk_details": [
                {
                    "category": "Port",
                    "title": "Critical services exposed",
                    "description": "Critical services are exposed to the internet",
                    "score": 15,
                    "affected_assets": ["22 (ssh)", "3389 (rdp)"]
                },
                {
                    "category": "HTTP Headers",
                    "title": "Missing security headers",
                    "description": "Critical security headers are missing",
                    "score": 10,
                    "affected_assets": ["Content-Security-Policy", "X-Frame-Options"]
                }
            ]
        }
        
        # Test AI analysis
        ai_results = analyze_risks("example.com", risk_data)
        
        # Verify results
        self.assertIsInstance(ai_results, dict)
        self.assertIn("summary", ai_results)
        self.assertIn("key_risks", ai_results)
        self.assertIn("recommendations", ai_results)
        
        # Verify the analysis contains meaningful content
        self.assertGreater(len(ai_results["summary"]), 0)
        self.assertIsInstance(ai_results["key_risks"], list)
        self.assertIsInstance(ai_results["recommendations"], list)


if __name__ == '__main__':
    unittest.main()
