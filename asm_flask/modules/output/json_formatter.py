#!/usr/bin/env python3
"""
JSON Output Formatter Module for Attack Surface Monitoring Tool
This module generates structured JSON reports from reconnaissance and analysis data.
"""

import json
import sys
import os
import datetime
from typing import Dict, Any, List, Optional


class JSONFormatter:
    """
    A class to format reconnaissance and analysis data into structured JSON reports.
    """

    def __init__(self, domain: str, recon_data: Dict[str, Any], risk_data: Dict[str, Any], 
                 ai_analysis: Dict[str, Any]):
        """
        Initialize the JSONFormatter with reconnaissance and analysis data.

        Args:
            domain (str): The target domain.
            recon_data (Dict[str, Any]): Reconnaissance data for the domain.
            risk_data (Dict[str, Any]): Risk data for the domain.
            ai_analysis (Dict[str, Any]): AI analysis results for the domain.
        """
        self.domain = domain
        self.recon_data = recon_data
        self.risk_data = risk_data
        self.ai_analysis = ai_analysis
        self.scan_date = datetime.datetime.now().strftime("%Y-%m-%d")

    def generate_report(self) -> Dict[str, Any]:
        """
        Generate a structured JSON report.

        Returns:
            Dict[str, Any]: The formatted JSON report.
        """
        print(f"[+] Generating JSON report for {self.domain}")
        
        # Create the base report structure
        report = {
            "domain": self.domain,
            "scan_date": self.scan_date,
            "risk_score": self.risk_data.get("risk_score", 0),
            "risk_summary": self.ai_analysis.get("summary", "No analysis available"),
            "subdomains": self._format_subdomains(),
            "dns_records": self._format_dns_records(),
            "open_ports": self._format_open_ports(),
            "tech_stack": self._format_tech_stack(),
            "headers": self._format_headers(),
            "ssl_info": self._format_ssl_info(),
            "osint_findings": self._format_osint_findings(),
            "sensitive_paths": self._format_sensitive_paths(),
            "risk_details": self._format_risk_details(),
            "recommendations": self.ai_analysis.get("recommendations", [])
        }
        
        print(f"[+] JSON report generated successfully")
        
        return report

    def save_report(self, output_file: str) -> None:
        """
        Generate and save the JSON report to a file.

        Args:
            output_file (str): Path to the output file.
        """
        report = self.generate_report()
        
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"[+] Report saved to {output_file}")
        
        except Exception as e:
            print(f"[!] Error saving report: {e}", file=sys.stderr)
            raise

    def _format_subdomains(self) -> List[Dict[str, Any]]:
        """
        Format subdomain data.

        Returns:
            List[Dict[str, Any]]: Formatted subdomain data.
        """
        formatted_subdomains = []
        
        if 'subdomains' in self.recon_data and self.recon_data['subdomains']:
            # If subdomains is already a list of dictionaries with detailed info
            if isinstance(self.recon_data['subdomains'][0], dict):
                formatted_subdomains = self.recon_data['subdomains']
            else:
                # If subdomains is just a list of strings, convert to dictionaries
                for subdomain in self.recon_data['subdomains']:
                    formatted_subdomains.append({
                        "hostname": subdomain,
                        "is_live": True  # Assuming all are live since they were detected
                    })
        
        return formatted_subdomains

    def _format_dns_records(self) -> Dict[str, Any]:
        """
        Format DNS record data.

        Returns:
            Dict[str, Any]: Formatted DNS record data.
        """
        if 'dns_records' in self.recon_data and self.recon_data['dns_records']:
            return self.recon_data['dns_records']
        
        return {}

    def _format_open_ports(self) -> List[Dict[str, Any]]:
        """
        Format open port data.

        Returns:
            List[Dict[str, Any]]: Formatted open port data.
        """
        if 'open_ports' in self.recon_data and self.recon_data['open_ports']:
            return self.recon_data['open_ports']
        
        return []

    def _format_tech_stack(self) -> List[str]:
        """
        Format technology stack data.

        Returns:
            List[str]: Formatted technology stack data.
        """
        if 'tech_stack' in self.recon_data and self.recon_data['tech_stack']:
            if isinstance(self.recon_data['tech_stack'], list):
                return self.recon_data['tech_stack']
            elif isinstance(self.recon_data['tech_stack'], dict) and 'technologies' in self.recon_data['tech_stack']:
                return self.recon_data['tech_stack']['technologies']
        
        return []

    def _format_headers(self) -> Dict[str, Any]:
        """
        Format HTTP header data.

        Returns:
            Dict[str, Any]: Formatted HTTP header data.
        """
        if 'headers' in self.recon_data and self.recon_data['headers']:
            # If it's already a dictionary of header values
            if isinstance(self.recon_data['headers'], dict) and not isinstance(list(self.recon_data['headers'].values())[0], dict):
                return self.recon_data['headers']
            
            # If it's a dictionary with detailed header info, extract just the values
            elif isinstance(self.recon_data['headers'], dict):
                headers = {}
                for header, info in self.recon_data['headers'].items():
                    if isinstance(info, dict) and 'value' in info:
                        headers[header] = info['value']
                    else:
                        headers[header] = info
                return headers
        
        return {}

    def _format_ssl_info(self) -> Dict[str, Any]:
        """
        Format SSL/TLS data.

        Returns:
            Dict[str, Any]: Formatted SSL/TLS data.
        """
        if 'ssl_info' in self.recon_data and self.recon_data['ssl_info']:
            return self.recon_data['ssl_info']
        
        return {}

    def _format_osint_findings(self) -> Dict[str, Any]:
        """
        Format OSINT and breach data.

        Returns:
            Dict[str, Any]: Formatted OSINT and breach data.
        """
        if 'osint_findings' in self.recon_data and self.recon_data['osint_findings']:
            return self.recon_data['osint_findings']
        
        return {}

    def _format_sensitive_paths(self) -> List[Dict[str, Any]]:
        """
        Format sensitive path data.

        Returns:
            List[Dict[str, Any]]: Formatted sensitive path data.
        """
        if 'sensitive_paths' in self.recon_data and self.recon_data['sensitive_paths']:
            # Check if it's already a list of dictionaries
            if isinstance(self.recon_data['sensitive_paths'], list) and isinstance(self.recon_data['sensitive_paths'][0], dict):
                return self.recon_data['sensitive_paths']
            
            # If it's just a list of strings, convert to dictionaries
            elif isinstance(self.recon_data['sensitive_paths'], list):
                return [{"path": path, "sensitivity": "medium"} for path in self.recon_data['sensitive_paths']]
        
        return []

    def _format_risk_details(self) -> List[Dict[str, Any]]:
        """
        Format risk detail data.

        Returns:
            List[Dict[str, Any]]: Formatted risk detail data.
        """
        if 'risk_details' in self.risk_data and self.risk_data['risk_details']:
            # We'll simplify the risk details for the final report
            simplified_risks = []
            
            for risk in self.risk_data['risk_details']:
                simplified_risks.append({
                    "category": risk.get("category", "Unknown"),
                    "title": risk.get("title", "Unknown risk"),
                    "description": risk.get("description", "No description"),
                    "severity": self._map_score_to_severity(risk.get("score", 0)),
                    "affected_assets": risk.get("affected_assets", [])
                })
            
            return simplified_risks
        
        return []

    def _map_score_to_severity(self, score: float) -> str:
        """
        Map a numerical risk score to a severity level.

        Args:
            score (float): The risk score.

        Returns:
            str: The severity level (Critical, High, Medium, Low, or Info).
        """
        if score >= 20:
            return "Critical"
        elif score >= 15:
            return "High"
        elif score >= 10:
            return "Medium"
        elif score >= 5:
            return "Low"
        else:
            return "Info"


def generate_json_report(domain: str, recon_data: Dict[str, Any], risk_data: Dict[str, Any], 
                        ai_analysis: Dict[str, Any], output_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to generate a JSON report.

    Args:
        domain (str): The target domain.
        recon_data (Dict[str, Any]): Reconnaissance data for the domain.
        risk_data (Dict[str, Any]): Risk data for the domain.
        ai_analysis (Dict[str, Any]): AI analysis results for the domain.
        output_file (Optional[str]): Path to the output file. If provided, the report will be saved to this file.

    Returns:
        Dict[str, Any]: The generated JSON report.
    """
    formatter = JSONFormatter(domain, recon_data, risk_data, ai_analysis)
    report = formatter.generate_report()
    
    if output_file:
        formatter.save_report(output_file)
    
    return report


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 4:
        target_domain = sys.argv[1]
        recon_file = sys.argv[2]
        risk_file = sys.argv[3]
        ai_file = sys.argv[4]
        output_file = sys.argv[5] if len(sys.argv) > 5 else f"{target_domain}_report.json"
        
        try:
            with open(recon_file, 'r') as f:
                recon_data = json.load(f)
            
            with open(risk_file, 'r') as f:
                risk_data = json.load(f)
            
            with open(ai_file, 'r') as f:
                ai_analysis = json.load(f)
            
            report = generate_json_report(target_domain, recon_data, risk_data, ai_analysis, output_file)
            print(f"Report generated and saved to {output_file}")
        
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    else:
        print("Usage: python json_formatter.py <domain> <recon_file> <risk_file> <ai_file> [output_file]", file=sys.stderr)
