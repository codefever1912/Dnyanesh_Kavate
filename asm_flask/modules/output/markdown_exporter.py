#!/usr/bin/env python3
"""
Markdown Exporter Module for Attack Surface Monitoring Tool
This module generates Markdown reports from JSON data.
"""

import json
import sys
import os
import datetime
from typing import Dict, Any, List, Optional


class MarkdownExporter:
    """
    A class to export JSON reports to Markdown format.
    """

    def __init__(self, report_data: Dict[str, Any]):
        """
        Initialize the MarkdownExporter with report data.

        Args:
            report_data (Dict[str, Any]): The JSON report data.
        """
        self.report_data = report_data
        self.domain = report_data.get("domain", "Unknown")
        self.scan_date = report_data.get("scan_date", datetime.datetime.now().strftime("%Y-%m-%d"))

    def generate_markdown(self) -> str:
        """
        Generate a Markdown report.

        Returns:
            str: The Markdown report.
        """
        print(f"[+] Generating Markdown report for {self.domain}")
        
        markdown = []
        
        # Title and summary
        markdown.append(f"# Attack Surface Monitoring Report: {self.domain}")
        markdown.append(f"**Scan Date:** {self.scan_date}")
        markdown.append(f"**Risk Score:** {self.report_data.get('risk_score', 0)}/100")
        markdown.append("")
        
        # Risk summary
        markdown.append("## Executive Summary")
        markdown.append(self.report_data.get("risk_summary", "No summary available."))
        markdown.append("")
        
        # Key recommendations
        if "recommendations" in self.report_data and self.report_data["recommendations"]:
            markdown.append("## Key Recommendations")
            for i, rec in enumerate(self.report_data["recommendations"], 1):
                markdown.append(f"{i}. {rec}")
            markdown.append("")
        
        # Subdomains
        if "subdomains" in self.report_data and self.report_data["subdomains"]:
            markdown.append("## Subdomains")
            markdown.append(f"Discovered {len(self.report_data['subdomains'])} subdomains:")
            markdown.append("")
            markdown.append("| Subdomain | Status |")
            markdown.append("| --- | --- |")
            
            for subdomain in self.report_data["subdomains"]:
                if isinstance(subdomain, dict):
                    hostname = subdomain.get("hostname", "Unknown")
                    status = "Live" if subdomain.get("is_live", True) else "Inactive"
                    markdown.append(f"| {hostname} | {status} |")
                else:
                    markdown.append(f"| {subdomain} | Unknown |")
            
            markdown.append("")
        
        # DNS Records
        if "dns_records" in self.report_data and self.report_data["dns_records"]:
            markdown.append("## DNS Records")
            
            for record_type, records in self.report_data["dns_records"].items():
                if records:
                    markdown.append(f"### {record_type} Records")
                    for record in records:
                        markdown.append(f"- `{record}`")
                    markdown.append("")
        
        # Open Ports
        if "open_ports" in self.report_data and self.report_data["open_ports"]:
            markdown.append("## Open Ports and Services")
            markdown.append("| Port | Protocol | Service | Version |")
            markdown.append("| --- | --- | --- | --- |")
            
            for port_info in self.report_data["open_ports"]:
                if isinstance(port_info, dict):
                    port = port_info.get("port", "Unknown")
                    protocol = port_info.get("protocol", "tcp")
                    service = port_info.get("service", "Unknown")
                    version = f"{port_info.get('product', '')} {port_info.get('version', '')}".strip()
                    markdown.append(f"| {port} | {protocol} | {service} | {version} |")
            
            markdown.append("")
        
        # Technology Stack
        if "tech_stack" in self.report_data and self.report_data["tech_stack"]:
            markdown.append("## Technology Stack")
            
            if isinstance(self.report_data["tech_stack"], list):
                for tech in self.report_data["tech_stack"]:
                    markdown.append(f"- {tech}")
            
            markdown.append("")
        
        # HTTP Headers
        if "headers" in self.report_data and self.report_data["headers"]:
            markdown.append("## HTTP Headers")
            markdown.append("| Header | Value |")
            markdown.append("| --- | --- |")
            
            for header, value in self.report_data["headers"].items():
                if isinstance(value, str):
                    # Truncate very long values
                    if len(value) > 100:
                        value = value[:97] + "..."
                    markdown.append(f"| {header} | `{value}` |")
            
            markdown.append("")
        
        # SSL/TLS Information
        if "ssl_info" in self.report_data and self.report_data["ssl_info"]:
            markdown.append("## SSL/TLS Configuration")
            
            ssl_info = self.report_data["ssl_info"]
            
            if "grade" in ssl_info:
                markdown.append(f"**Grade:** {ssl_info['grade']}")
            
            if "certificate" in ssl_info and ssl_info["certificate"]:
                cert = ssl_info["certificate"]
                markdown.append("")
                markdown.append("### Certificate Information")
                
                if "subject" in cert and "common_name" in cert["subject"]:
                    markdown.append(f"**Subject:** {cert['subject'].get('common_name', 'Unknown')}")
                
                if "issuer" in cert and "common_name" in cert["issuer"]:
                    markdown.append(f"**Issuer:** {cert['issuer'].get('common_name', 'Unknown')}")
                
                if "not_before" in cert:
                    markdown.append(f"**Valid From:** {cert.get('not_before', 'Unknown')}")
                
                if "not_after" in cert:
                    markdown.append(f"**Valid Until:** {cert.get('not_after', 'Unknown')}")
                
                if "expired" in cert:
                    markdown.append(f"**Expired:** {'Yes' if cert.get('expired', False) else 'No'}")
                
                if "self_signed" in cert:
                    markdown.append(f"**Self-Signed:** {'Yes' if cert.get('self_signed', False) else 'No'}")
            
            if "protocols" in ssl_info and ssl_info["protocols"]:
                markdown.append("")
                markdown.append("### Supported Protocols")
                
                for protocol, supported in ssl_info["protocols"].items():
                    status = "Supported" if supported else "Not Supported"
                    markdown.append(f"- {protocol}: {status}")
            
            if "vulnerabilities" in ssl_info and ssl_info["vulnerabilities"]:
                markdown.append("")
                markdown.append("### Vulnerabilities")
                
                for vuln in ssl_info["vulnerabilities"]:
                    markdown.append(f"- {vuln}")
            
            markdown.append("")
        
        # Sensitive Paths
        if "sensitive_paths" in self.report_data and self.report_data["sensitive_paths"]:
            markdown.append("## Sensitive Paths")
            markdown.append("| Path | Sensitivity | Status Code |")
            markdown.append("| --- | --- | --- |")
            
            for path_info in self.report_data["sensitive_paths"]:
                if isinstance(path_info, dict):
                    path = path_info.get("path", "Unknown")
                    sensitivity = path_info.get("sensitivity", "medium").capitalize()
                    status_code = path_info.get("status_code", "Unknown")
                    markdown.append(f"| {path} | {sensitivity} | {status_code} |")
                else:
                    markdown.append(f"| {path_info} | Unknown | Unknown |")
            
            markdown.append("")
        
        # OSINT Findings
        if "osint_findings" in self.report_data and self.report_data["osint_findings"]:
            markdown.append("## OSINT and Breach Findings")
            
            osint = self.report_data["osint_findings"]
            
            if "breach_count" in osint:
                markdown.append(f"**Total Breaches:** {osint.get('breach_count', 0)}")
            
            if "emails_found" in osint and osint["emails_found"]:
                markdown.append("")
                markdown.append(f"**Emails Found:** {len(osint['emails_found'])}")
                
                if len(osint['emails_found']) <= 10:
                    for email in osint['emails_found']:
                        markdown.append(f"- {email}")
                else:
                    for email in osint['emails_found'][:10]:
                        markdown.append(f"- {email}")
                    markdown.append(f"- ... and {len(osint['emails_found']) - 10} more")
            
            if "breaches" in osint and osint["breaches"]:
                markdown.append("")
                markdown.append("### Breach Details")
                
                for breach in osint["breaches"]:
                    if isinstance(breach, dict):
                        title = breach.get("title", "Unknown breach")
                        date = breach.get("breach_date", "Unknown date")
                        source = breach.get("source", "Unknown source")
                        
                        markdown.append(f"#### {title}")
                        markdown.append(f"**Date:** {date}")
                        markdown.append(f"**Source:** {source}")
                        
                        if "data_classes" in breach and breach["data_classes"]:
                            markdown.append("**Exposed Data:**")
                            for data_class in breach["data_classes"]:
                                markdown.append(f"- {data_class}")
                        
                        markdown.append("")
            
            markdown.append("")
        
        # Risk Details
        if "risk_details" in self.report_data and self.report_data["risk_details"]:
            markdown.append("## Detailed Risk Findings")
            
            # Group risks by category
            risks_by_category = {}
            for risk in self.report_data["risk_details"]:
                category = risk.get("category", "Other")
                if category not in risks_by_category:
                    risks_by_category[category] = []
                risks_by_category[category].append(risk)
            
            for category, risks in risks_by_category.items():
                markdown.append(f"### {category} Risks")
                
                for risk in risks:
                    title = risk.get("title", "Unknown risk")
                    severity = risk.get("severity", "Unknown")
                    description = risk.get("description", "No description")
                    
                    markdown.append(f"#### {title} ({severity})")
                    markdown.append(description)
                    
                    if "affected_assets" in risk and risk["affected_assets"]:
                        markdown.append("**Affected Assets:**")
                        for asset in risk["affected_assets"][:5]:
                            markdown.append(f"- {asset}")
                        if len(risk["affected_assets"]) > 5:
                            markdown.append(f"- ... and {len(risk['affected_assets']) - 5} more")
                    
                    markdown.append("")
            
            markdown.append("")
        
        # Footer
        markdown.append("---")
        markdown.append(f"Report generated by Attack Surface Monitoring Tool on {self.scan_date}")
        
        return "\n".join(markdown)

    def save_markdown(self, output_file: str) -> None:
        """
        Generate and save the Markdown report to a file.

        Args:
            output_file (str): Path to the output file.
        """
        markdown = self.generate_markdown()
        
        try:
            with open(output_file, 'w') as f:
                f.write(markdown)
            
            print(f"[+] Markdown report saved to {output_file}")
        
        except Exception as e:
            print(f"[!] Error saving Markdown report: {e}", file=sys.stderr)
            raise


def generate_markdown_report(report_data: Dict[str, Any], output_file: Optional[str] = None) -> str:
    """
    Convenience function to generate a Markdown report.

    Args:
        report_data (Dict[str, Any]): The JSON report data.
        output_file (Optional[str]): Path to the output file. If provided, the report will be saved to this file.

    Returns:
        str: The generated Markdown report.
    """
    exporter = MarkdownExporter(report_data)
    markdown = exporter.generate_markdown()
    
    if output_file:
        exporter.save_markdown(output_file)
    
    return markdown


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 1:
        report_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        
        try:
            with open(report_file, 'r') as f:
                report_data = json.load(f)
            
            markdown = generate_markdown_report(report_data, output_file)
            
            if not output_file:
                print(markdown)
        
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    else:
        print("Usage: python markdown_exporter.py <report_file> [output_file]", file=sys.stderr)
