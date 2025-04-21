#!/usr/bin/env python3
"""
HTML Exporter Module for Attack Surface Monitoring Tool
This module generates HTML reports from JSON data.
"""

import json
import sys
import os
import datetime
from typing import Dict, Any, List, Optional


class HTMLExporter:
    """
    A class to export JSON reports to HTML format.
    """

    def __init__(self, report_data: Dict[str, Any]):
        """
        Initialize the HTMLExporter with report data.

        Args:
            report_data (Dict[str, Any]): The JSON report data.
        """
        self.report_data = report_data
        self.domain = report_data.get("domain", "Unknown")
        self.scan_date = report_data.get("scan_date", datetime.datetime.now().strftime("%Y-%m-%d"))
        self.risk_score = report_data.get("risk_score", 0)

    def generate_html(self) -> str:
        """
        Generate an HTML report.

        Returns:
            str: The HTML report.
        """
        print(f"[+] Generating HTML report for {self.domain}")
        
        # Define the HTML template
        html = []
        
        # HTML header
        html.append('<!DOCTYPE html>')
        html.append('<html lang="en">')
        html.append('<head>')
        html.append('    <meta charset="UTF-8">')
        html.append('    <meta name="viewport" content="width=device-width, initial-scale=1.0">')
        html.append(f'    <title>ASM Report: {self.domain}</title>')
        html.append('    <style>')
        html.append(self._get_css_styles())
        html.append('    </style>')
        html.append('</head>')
        html.append('<body>')
        
        # Report header
        html.append('    <header>')
        html.append(f'        <h1>Attack Surface Monitoring Report: {self.domain}</h1>')
        html.append('        <div class="report-meta">')
        html.append(f'            <p><strong>Scan Date:</strong> {self.scan_date}</p>')
        html.append(f'            <p><strong>Risk Score:</strong> <span class="{self._get_risk_class(self.risk_score)}">{self.risk_score}/100</span></p>')
        html.append('        </div>')
        html.append('    </header>')
        
        # Main content
        html.append('    <main>')
        
        # Executive Summary
        html.append('        <section class="summary">')
        html.append('            <h2>Executive Summary</h2>')
        html.append(f'            <p>{self.report_data.get("risk_summary", "No summary available.")}</p>')
        html.append('        </section>')
        
        # Key Recommendations
        if "recommendations" in self.report_data and self.report_data["recommendations"]:
            html.append('        <section class="recommendations">')
            html.append('            <h2>Key Recommendations</h2>')
            html.append('            <ol>')
            for rec in self.report_data["recommendations"]:
                html.append(f'                <li>{rec}</li>')
            html.append('            </ol>')
            html.append('        </section>')
        
        # Risk Details
        if "risk_details" in self.report_data and self.report_data["risk_details"]:
            html.append('        <section class="risk-details">')
            html.append('            <h2>Risk Details</h2>')
            
            # Group risks by category
            risks_by_category = {}
            for risk in self.report_data["risk_details"]:
                category = risk.get("category", "Other")
                if category not in risks_by_category:
                    risks_by_category[category] = []
                risks_by_category[category].append(risk)
            
            for category, risks in risks_by_category.items():
                html.append(f'            <div class="risk-category">')
                html.append(f'                <h3>{category} Risks</h3>')
                
                for risk in risks:
                    title = risk.get("title", "Unknown risk")
                    severity = risk.get("severity", "Unknown")
                    severity_class = severity.lower() if severity in ["Critical", "High", "Medium", "Low"] else "info"
                    description = risk.get("description", "No description")
                    
                    html.append(f'                <div class="risk-item">')
                    html.append(f'                    <h4>{title} <span class="severity {severity_class}">{severity}</span></h4>')
                    html.append(f'                    <p>{description}</p>')
                    
                    if "affected_assets" in risk and risk["affected_assets"]:
                        html.append(f'                    <div class="affected-assets">')
                        html.append(f'                        <h5>Affected Assets:</h5>')
                        html.append(f'                        <ul>')
                        for asset in risk["affected_assets"][:10]:
                            html.append(f'                            <li>{asset}</li>')
                        if len(risk["affected_assets"]) > 10:
                            html.append(f'                            <li>... and {len(risk["affected_assets"]) - 10} more</li>')
                        html.append(f'                        </ul>')
                        html.append(f'                    </div>')
                    
                    html.append(f'                </div>')
                
                html.append(f'            </div>')
            
            html.append('        </section>')
        
        # Subdomains
        if "subdomains" in self.report_data and self.report_data["subdomains"]:
            html.append('        <section class="subdomains">')
            html.append('            <h2>Subdomains</h2>')
            html.append(f'            <p>Discovered {len(self.report_data["subdomains"])} subdomains:</p>')
            html.append('            <div class="table-container">')
            html.append('                <table>')
            html.append('                    <thead>')
            html.append('                        <tr>')
            html.append('                            <th>Subdomain</th>')
            html.append('                            <th>Status</th>')
            html.append('                        </tr>')
            html.append('                    </thead>')
            html.append('                    <tbody>')
            
            for subdomain in self.report_data["subdomains"]:
                if isinstance(subdomain, dict):
                    hostname = subdomain.get("hostname", "Unknown")
                    status = "Live" if subdomain.get("is_live", True) else "Inactive"
                    status_class = "live" if status == "Live" else "inactive"
                    html.append(f'                        <tr>')
                    html.append(f'                            <td>{hostname}</td>')
                    html.append(f'                            <td class="{status_class}">{status}</td>')
                    html.append(f'                        </tr>')
                else:
                    html.append(f'                        <tr>')
                    html.append(f'                            <td>{subdomain}</td>')
                    html.append(f'                            <td>Unknown</td>')
                    html.append(f'                        </tr>')
            
            html.append('                    </tbody>')
            html.append('                </table>')
            html.append('            </div>')
            html.append('        </section>')
        
        # Open Ports
        if "open_ports" in self.report_data and self.report_data["open_ports"]:
            html.append('        <section class="open-ports">')
            html.append('            <h2>Open Ports and Services</h2>')
            html.append('            <div class="table-container">')
            html.append('                <table>')
            html.append('                    <thead>')
            html.append('                        <tr>')
            html.append('                            <th>Port</th>')
            html.append('                            <th>Protocol</th>')
            html.append('                            <th>Service</th>')
            html.append('                            <th>Version</th>')
            html.append('                        </tr>')
            html.append('                    </thead>')
            html.append('                    <tbody>')
            
            for port_info in self.report_data["open_ports"]:
                if isinstance(port_info, dict):
                    port = port_info.get("port", "Unknown")
                    protocol = port_info.get("protocol", "tcp")
                    service = port_info.get("service", "Unknown")
                    version = f"{port_info.get('product', '')} {port_info.get('version', '')}".strip()
                    html.append(f'                        <tr>')
                    html.append(f'                            <td>{port}</td>')
                    html.append(f'                            <td>{protocol}</td>')
                    html.append(f'                            <td>{service}</td>')
                    html.append(f'                            <td>{version}</td>')
                    html.append(f'                        </tr>')
            
            html.append('                    </tbody>')
            html.append('                </table>')
            html.append('            </div>')
            html.append('        </section>')
        
        # Technology Stack
        if "tech_stack" in self.report_data and self.report_data["tech_stack"]:
            html.append('        <section class="tech-stack">')
            html.append('            <h2>Technology Stack</h2>')
            html.append('            <div class="tech-list">')
            
            if isinstance(self.report_data["tech_stack"], list):
                for tech in self.report_data["tech_stack"]:
                    html.append(f'                <span class="tech-badge">{tech}</span>')
            
            html.append('            </div>')
            html.append('        </section>')
        
        # SSL/TLS Information
        if "ssl_info" in self.report_data and self.report_data["ssl_info"]:
            html.append('        <section class="ssl-info">')
            html.append('            <h2>SSL/TLS Configuration</h2>')
            
            ssl_info = self.report_data["ssl_info"]
            
            if "grade" in ssl_info:
                grade = ssl_info["grade"]
                grade_class = self._get_grade_class(grade)
                html.append(f'            <p><strong>Grade:</strong> <span class="grade {grade_class}">{grade}</span></p>')
            
            if "certificate" in ssl_info and ssl_info["certificate"]:
                cert = ssl_info["certificate"]
                html.append('            <div class="cert-info">')
                html.append('                <h3>Certificate Information</h3>')
                html.append('                <table>')
                
                if "subject" in cert and "common_name" in cert["subject"]:
                    html.append('                    <tr>')
                    html.append('                        <th>Subject</th>')
                    html.append(f'                        <td>{cert["subject"].get("common_name", "Unknown")}</td>')
                    html.append('                    </tr>')
                
                if "issuer" in cert and "common_name" in cert["issuer"]:
                    html.append('                    <tr>')
                    html.append('                        <th>Issuer</th>')
                    html.append(f'                        <td>{cert["issuer"].get("common_name", "Unknown")}</td>')
                    html.append('                    </tr>')
                
                if "not_before" in cert:
                    html.append('                    <tr>')
                    html.append('                        <th>Valid From</th>')
                    html.append(f'                        <td>{cert.get("not_before", "Unknown")}</td>')
                    html.append('                    </tr>')
                
                if "not_after" in cert:
                    html.append('                    <tr>')
                    html.append('                        <th>Valid Until</th>')
                    html.append(f'                        <td>{cert.get("not_after", "Unknown")}</td>')
                    html.append('                    </tr>')
                
                if "expired" in cert:
                    is_expired = cert.get("expired", False)
                    status_class = "error" if is_expired else "success"
                    html.append('                    <tr>')
                    html.append('                        <th>Expired</th>')
                    html.append(f'                        <td class="{status_class}">{"Yes" if is_expired else "No"}</td>')
                    html.append('                    </tr>')
                
                if "self_signed" in cert:
                    is_self_signed = cert.get("self_signed", False)
                    status_class = "warning" if is_self_signed else "success"
                    html.append('                    <tr>')
                    html.append('                        <th>Self-Signed</th>')
                    html.append(f'                        <td class="{status_class}">{"Yes" if is_self_signed else "No"}</td>')
                    html.append('                    </tr>')
                
                html.append('                </table>')
                html.append('            </div>')
            
            if "protocols" in ssl_info and ssl_info["protocols"]:
                html.append('            <div class="protocol-info">')
                html.append('                <h3>Supported Protocols</h3>')
                html.append('                <table>')
                html.append('                    <tr>')
                html.append('                        <th>Protocol</th>')
                html.append('                        <th>Status</th>')
                html.append('                    </tr>')
                
                for protocol, supported in ssl_info["protocols"].items():
                    status_class = ""
                    if protocol in ["SSLv2", "SSLv3"]:
                        status_class = "error" if supported else "success"
                    elif protocol in ["TLSv1", "TLSv1.1"]:
                        status_class = "warning" if supported else "success"
                    elif protocol in ["TLSv1.2", "TLSv1.3"]:
                        status_class = "success" if supported else "warning"
                    
                    html.append('                    <tr>')
                    html.append(f'                        <td>{protocol}</td>')
                    html.append(f'                        <td class="{status_class}">{"Supported" if supported else "Not Supported"}</td>')
                    html.append('                    </tr>')
                
                html.append('                </table>')
                html.append('            </div>')
            
            if "vulnerabilities" in ssl_info and ssl_info["vulnerabilities"]:
                html.append('            <div class="ssl-vulnerabilities">')
                html.append('                <h3>Vulnerabilities</h3>')
                html.append('                <ul class="error-list">')
                
                for vuln in ssl_info["vulnerabilities"]:
                    html.append(f'                    <li>{vuln}</li>')
                
                html.append('                </ul>')
                html.append('            </div>')
            
            html.append('        </section>')
        
        # Sensitive Paths
        if "sensitive_paths" in self.report_data and self.report_data["sensitive_paths"]:
            html.append('        <section class="sensitive-paths">')
            html.append('            <h2>Sensitive Paths</h2>')
            html.append('            <div class="table-container">')
            html.append('                <table>')
            html.append('                    <thead>')
            html.append('                        <tr>')
            html.append('                            <th>Path</th>')
            html.append('                            <th>Sensitivity</th>')
            html.append('                            <th>Status Code</th>')
            html.append('                        </tr>')
            html.append('                    </thead>')
            html.append('                    <tbody>')
            
            for path_info in self.report_data["sensitive_paths"]:
                if isinstance(path_info, dict):
                    path = path_info.get("path", "Unknown")
                    sensitivity = path_info.get("sensitivity", "medium").capitalize()
                    sensitivity_class = sensitivity.lower()
                    status_code = path_info.get("status_code", "Unknown")
                    html.append(f'                        <tr>')
                    html.append(f'                            <td>{path}</td>')
                    html.append(f'                            <td class="{sensitivity_class}">{sensitivity}</td>')
                    html.append(f'                            <td>{status_code}</td>')
                    html.append(f'                        </tr>')
                else:
                    html.append(f'                        <tr>')
                    html.append(f'                            <td>{path_info}</td>')
                    html.append(f'                            <td>Unknown</td>')
                    html.append(f'                            <td>Unknown</td>')
                    html.append(f'                        </tr>')
            
            html.append('                    </tbody>')
            html.append('                </table>')
            html.append('            </div>')
            html.append('        </section>')
        
        # OSINT Findings
        if "osint_findings" in self.report_data and self.report_data["osint_findings"]:
            html.append('        <section class="osint-findings">')
            html.append('            <h2>OSINT and Breach Findings</h2>')
            
            osint = self.report_data["osint_findings"]
            
            if "breach_count" in osint:
                breach_count = osint.get("breach_count", 0)
                breach_class = "error" if breach_count > 0 else "success"
                html.append(f'            <p><strong>Total Breaches:</strong> <span class="{breach_class}">{breach_count}</span></p>')
            
            if "emails_found" in osint and osint["emails_found"]:
                html.append('            <div class="emails-found">')
                html.append(f'                <h3>Emails Found ({len(osint["emails_found"])})</h3>')
                html.append('                <div class="email-list">')
                
                for email in osint["emails_found"][:20]:
                    html.append(f'                    <span class="email-badge">{email}</span>')
                
                if len(osint["emails_found"]) > 20:
                    html.append(f'                    <span class="email-badge more">+{len(osint["emails_found"]) - 20} more</span>')
                
                html.append('                </div>')
                html.append('            </div>')
            
            if "breaches" in osint and osint["breaches"]:
                html.append('            <div class="breach-details">')
                html.append('                <h3>Breach Details</h3>')
                
                for breach in osint["breaches"]:
                    if isinstance(breach, dict):
                        title = breach.get("title", "Unknown breach")
                        date = breach.get("breach_date", "Unknown date")
                        source = breach.get("source", "Unknown source")
                        
                        html.append('                <div class="breach-item">')
                        html.append(f'                    <h4>{title}</h4>')
                        html.append(f'                    <p><strong>Date:</strong> {date}</p>')
                        html.append(f'                    <p><strong>Source:</strong> {source}</p>')
                        
                        if "data_classes" in breach and breach["data_classes"]:
                            html.append('                    <div class="data-classes">')
                            html.append('                        <p><strong>Exposed Data:</strong></p>')
                            html.append('                        <ul>')
                            for data_class in breach["data_classes"]:
                                html.append(f'                            <li>{data_class}</li>')
                            html.append('                        </ul>')
                            html.append('                    </div>')
                        
                        html.append('                </div>')
                
                html.append('            </div>')
            
            html.append('        </section>')
        
        html.append('    </main>')
        
        # Footer
        html.append('    <footer>')
        html.append(f'        <p>Report generated by Attack Surface Monitoring Tool on {self.scan_date}</p>')
        html.append('    </footer>')
        
        # Add JavaScript for interactive elements
        html.append('    <script>')
        html.append('        document.addEventListener("DOMContentLoaded", function() {')
        html.append('            // Add collapsible functionality to sections')
        html.append('            const sections = document.querySelectorAll("section > h2");')
        html.append('            sections.forEach(section => {')
        html.append('                section.addEventListener("click", function() {')
        html.append('                    this.parentElement.classList.toggle("collapsed");')
        html.append('                });')
        html.append('            });')
        html.append('        });')
        html.append('    </script>')
        
        html.append('</body>')
        html.append('</html>')
        
        return '\n'.join(html)

    def _get_css_styles(self) -> str:
        """
        Get CSS styles for the HTML report.

        Returns:
            str: CSS styles.
        """
        return '''
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --accent-color: #e74c3c;
            --success-color: #2ecc71;
            --warning-color: #f39c12;
            --error-color: #e74c3c;
            --info-color: #3498db;
            --bg-color: #f8f9fa;
            --text-color: #333;
            --border-color: #ddd;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background-color: var(--bg-color);
            padding: 0;
            margin: 0;
        }
        
        header {
            background-color: var(--primary-color);
            color: white;
            padding: 1.5rem;
            text-align: center;
        }
        
        header h1 {
            margin-bottom: 1rem;
        }
        
        .report-meta {
            display: flex;
            justify-content: center;
            gap: 2rem;
        }
        
        main {
            max-width: 1200px;
            margin: 0 auto;
            padding: 1rem;
        }
        
        section {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            margin-bottom: 1.5rem;
            padding: 1.5rem;
            overflow: hidden;
        }
        
        section h2 {
            border-bottom: 2px solid var(--secondary-color);
            padding-bottom: 0.5rem;
            margin-bottom: 1rem;
            cursor: pointer;
            position: relative;
        }
        
        section h2::after {
            content: "";
            position: absolute;
            right: 0;
            transition: transform 0.3s;
        }
        
        section.collapsed h2::after {
            transform: rotate(-90deg);
        }
        
        section.collapsed > *:not(h2) {
            display: none;
        }
        
        h3 {
            margin: 1rem 0;
            color: var(--primary-color);
        }
        
        h4 {
            margin: 0.8rem 0;
            color: var(--primary-color);
        }
        
        p {
            margin-bottom: 1rem;
        }
        
        .table-container {
            overflow-x: auto;
            margin-bottom: 1rem;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1rem;
        }
        
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        
        th {
            background-color: var(--primary-color);
            color: white;
        }
        
        tr:nth-child(even) {
            background-color: rgba(0,0,0,0.02);
        }
        
        .risk-item {
            border-left: 3px solid var(--border-color);
            padding-left: 1rem;
            margin-bottom: 1.5rem;
        }
        
        .risk-category {
            margin-bottom: 2rem;
        }
        
        .severity {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 3px;
            font-size: 0.8rem;
            margin-left: 0.5rem;
        }
        
        .critical {
            background-color: var(--error-color);
            color: white;
        }
        
        .high {
            background-color: #ff6b6b;
            color: white;
        }
        
        .medium {
            background-color: var(--warning-color);
            color: white;
        }
        
        .low {
            background-color: #74b9ff;
            color: white;
        }
        
        .info {
            background-color: #a29bfe;
            color: white;
        }
        
        .grade {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 3px;
            font-weight: bold;
        }
        
        .grade-a {
            background-color: var(--success-color);
            color: white;
        }
        
        .grade-b {
            background-color: #74b9ff;
            color: white;
        }
        
        .grade-c {
            background-color: var(--warning-color);
            color: white;
        }
        
        .grade-d, .grade-f {
            background-color: var(--error-color);
            color: white;
        }
        
        .live {
            color: var(--success-color);
            font-weight: bold;
        }
        
        .inactive {
            color: var(--error-color);
        }
        
        .success {
            color: var(--success-color);
        }
        
        .warning {
            color: var(--warning-color);
        }
        
        .error {
            color: var(--error-color);
        }
        
        .error-list li {
            color: var(--error-color);
            margin-left: 1.5rem;
            margin-bottom: 0.5rem;
        }
        
        .tech-list, .email-list {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }
        
        .tech-badge, .email-badge {
            background-color: var(--secondary-color);
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 3px;
            font-size: 0.9rem;
        }
        
        .email-badge.more {
            background-color: var(--primary-color);
        }
        
        .breach-item {
            background-color: rgba(0,0,0,0.02);
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 1rem;
        }
        
        .affected-assets {
            background-color: rgba(0,0,0,0.02);
            padding: 0.5rem 1rem;
            border-radius: 3px;
            margin-top: 0.5rem;
        }
        
        .affected-assets h5 {
            margin-bottom: 0.5rem;
        }
        
        .affected-assets ul {
            margin-left: 1.5rem;
        }
        
        footer {
            text-align: center;
            padding: 1rem;
            background-color: var(--primary-color);
            color: white;
            font-size: 0.9rem;
        }
        
        @media (max-width: 768px) {
            .report-meta {
                flex-direction: column;
                gap: 0.5rem;
            }
            
            section {
                padding: 1rem;
            }
        }
        '''

    def _get_risk_class(self, score: int) -> str:
        """
        Get the CSS class for a risk score.

        Args:
            score (int): The risk score.

        Returns:
            str: The CSS class.
        """
        if score >= 85:
            return "critical"
        elif score >= 70:
            return "high"
        elif score >= 50:
            return "medium"
        elif score >= 25:
            return "low"
        else:
            return "info"

    def _get_grade_class(self, grade: str) -> str:
        """
        Get the CSS class for an SSL grade.

        Args:
            grade (str): The SSL grade.

        Returns:
            str: The CSS class.
        """
        if grade.startswith('A'):
            return "grade-a"
        elif grade.startswith('B'):
            return "grade-b"
        elif grade.startswith('C'):
            return "grade-c"
        elif grade.startswith('D'):
            return "grade-d"
        else:
            return "grade-f"

    def save_html(self, output_file: str) -> None:
        """
        Generate and save the HTML report to a file.

        Args:
            output_file (str): Path to the output file.
        """
        html = self.generate_html()
        
        try:
            with open(output_file, 'w') as f:
                f.write(html)
            
            print(f"[+] HTML report saved to {output_file}")
        
        except Exception as e:
            print(f"[!] Error saving HTML report: {e}", file=sys.stderr)
            raise


def generate_html_report(report_data: Dict[str, Any], output_file: Optional[str] = None) -> str:
    """
    Convenience function to generate an HTML report.

    Args:
        report_data (Dict[str, Any]): The JSON report data.
        output_file (Optional[str]): Path to the output file. If provided, the report will be saved to this file.

    Returns:
        str: The generated HTML report.
    """
    exporter = HTMLExporter(report_data)
    html = exporter.generate_html()
    
    if output_file:
        exporter.save_html(output_file)
    
    return html


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 1:
        report_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        
        try:
            with open(report_file, 'r') as f:
                report_data = json.load(f)
            
            html = generate_html_report(report_data, output_file)
            
            if not output_file:
                print("HTML report generated (not saved to file)")
        
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    else:
        print("Usage: python html_exporter.py <report_file> [output_file]", file=sys.stderr)
