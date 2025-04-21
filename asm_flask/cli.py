#!/usr/bin/env python3
"""
Command Line Interface for Attack Surface Monitoring Tool
This module provides a CLI for the ASM tool.
"""

import argparse
import sys
import os
import json
import time
import csv
from typing import List, Dict, Any, Optional
from datetime import datetime

# Import modules
from modules.input.csv_reader import read_domains_from_csv
from modules.reconnaissance.subdomain_enum import enumerate_subdomains
from modules.reconnaissance.live_subdomain import check_live_subdomains
from modules.reconnaissance.whois_dns import analyze_domain as analyze_whois_dns
from modules.reconnaissance.port_scanner import scan_ports
from modules.reconnaissance.service_fingerprint import fingerprint_services
from modules.reconnaissance.tech_detector import detect_technologies
from modules.reconnaissance.ssl_analyzer import analyze_ssl
from modules.reconnaissance.header_security import audit_headers
from modules.reconnaissance.path_discovery import discover_paths
from modules.reconnaissance.osint_breach import check_breaches
from modules.risk_analysis.risk_scorer import calculate_risk_score
from modules.risk_analysis.ai_analyzer import analyze_risks
from modules.output.json_formatter import generate_json_report
from modules.output.markdown_exporter import generate_markdown_report
from modules.output.html_exporter import generate_html_report


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Attack Surface Monitoring Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single domain
  python cli.py -d example.com -o output_dir
  
  # Scan multiple domains from a CSV file
  python cli.py -i domains.csv -o output_dir
  
  # Scan with specific modules
  python cli.py -d example.com -m subdomain,port,ssl -o output_dir
  
  # Export as markdown and HTML
  python cli.py -d example.com -o output_dir -f json,md,html
        """
    )
    
    # Input options
    input_group = parser.add_argument_group("Input Options")
    input_group.add_argument("-d", "--domain", help="Target domain to scan")
    input_group.add_argument("-i", "--input", help="Input CSV file with domains")
    
    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("-o", "--output", required=True, help="Output directory for reports")
    output_group.add_argument(
        "-f", "--format", 
        default="json", 
        help="Output format(s), comma-separated (json,md,html)"
    )
    
    # Scanning options
    scan_group = parser.add_argument_group("Scanning Options")
    scan_group.add_argument(
        "-m", "--modules",
        default="all",
        help="Modules to run, comma-separated (subdomain,live,dns,port,service,tech,ssl,header,path,osint,all)"
    )
    scan_group.add_argument(
        "--wordlist-size",
        choices=["small", "medium", "large"],
        default="medium",
        help="Wordlist size for path discovery (default: medium)"
    )
    scan_group.add_argument(
        "--port-range",
        default="1-1000",
        help="Port range for scanning (default: 1-1000)"
    )
    scan_group.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of threads for concurrent operations (default: 10)"
    )
    scan_group.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout in seconds for network operations (default: 10)"
    )
    
    # Misc options
    misc_group = parser.add_argument_group("Miscellaneous Options")
    misc_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    misc_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    
    return parser.parse_args()


def print_banner():
    """Print the tool banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   █████╗ ███████╗███╗   ███╗    ████████╗ ██████╗  ██████╗ ██╗     ║
    ║  ██╔══██╗██╔════╝████╗ ████║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ║
    ║  ███████║███████╗██╔████╔██║       ██║   ██║   ██║██║   ██║██║     ║
    ║  ██╔══██║╚════██║██║╚██╔╝██║       ██║   ██║   ██║██║   ██║██║     ║
    ║  ██║  ██║███████║██║ ╚═╝ ██║       ██║   ╚██████╔╝╚██████╔╝███████╗║
    ║  ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝║
    ║                                                           ║
    ║           Attack Surface Monitoring Tool                  ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def validate_args(args):
    """Validate command line arguments."""
    if not args.domain and not args.input:
        print("Error: Either --domain or --input must be specified.")
        sys.exit(1)
    
    if args.domain and args.input:
        print("Warning: Both --domain and --input specified. Using --domain.")
    
    if args.input and not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' does not exist.")
        sys.exit(1)
    
    if not os.path.exists(args.output):
        try:
            os.makedirs(args.output)
            print(f"Created output directory: {args.output}")
        except Exception as e:
            print(f"Error creating output directory: {e}")
            sys.exit(1)


def get_domains(args) -> List[str]:
    """Get domains from command line arguments or input file."""
    if args.domain:
        return [args.domain]
    
    if args.input:
        try:
            return read_domains_from_csv(args.input)
        except Exception as e:
            print(f"Error reading domains from CSV: {e}")
            sys.exit(1)
    
    return []


def scan_domain(domain: str, args) -> Dict[str, Any]:
    """
    Scan a single domain with all or selected modules.
    
    Args:
        domain (str): The domain to scan.
        args: Command line arguments.
        
    Returns:
        Dict[str, Any]: Reconnaissance data.
    """
    print(f"\n[+] Starting scan for {domain}")
    start_time = time.time()
    
    # Initialize results
    results = {
        "domain": domain,
        "scan_date": datetime.now().strftime("%Y-%m-%d"),
        "subdomains": [],
        "dns_records": {},
        "open_ports": [],
        "tech_stack": [],
        "headers": {},
        "ssl_info": {},
        "osint_findings": {},
        "sensitive_paths": []
    }
    
    modules = args.modules.lower().split(",")
    run_all = "all" in modules
    
    # Subdomain enumeration
    if run_all or "subdomain" in modules:
        print(f"\n[+] Running subdomain enumeration for {domain}")
        try:
            subdomains = enumerate_subdomains(domain)
            results["subdomains"] = subdomains
            print(f"[+] Found {len(subdomains)} subdomains")
        except Exception as e:
            print(f"[!] Error during subdomain enumeration: {e}")
    
    # Live subdomain detection
    if run_all or "live" in modules:
        if results["subdomains"]:
            print(f"\n[+] Running live subdomain detection for {len(results['subdomains'])} subdomains")
            try:
                live_subdomains = check_live_subdomains(results["subdomains"])
                # Update subdomains with live status
                subdomain_details = []
                for subdomain in results["subdomains"]:
                    is_live = any(ls["subdomain"] == subdomain for ls in live_subdomains)
                    subdomain_details.append({
                        "hostname": subdomain,
                        "is_live": is_live
                    })
                results["subdomains"] = subdomain_details
                print(f"[+] Found {len(live_subdomains)} live subdomains")
            except Exception as e:
                print(f"[!] Error during live subdomain detection: {e}")
    
    # WHOIS & DNS records
    if run_all or "dns" in modules:
        print(f"\n[+] Running WHOIS & DNS analysis for {domain}")
        try:
            dns_results = analyze_whois_dns(domain)
            results["whois"] = dns_results.get("whois", {})
            results["dns_records"] = dns_results.get("dns_records", {})
            print(f"[+] Completed WHOIS & DNS analysis")
        except Exception as e:
            print(f"[!] Error during WHOIS & DNS analysis: {e}")
    
    # Port scanning
    if run_all or "port" in modules:
        print(f"\n[+] Running port scan for {domain}")
        try:
            port_results = scan_ports(domain, args.port_range)
            results["open_ports"] = port_results.get("open_ports", [])
            print(f"[+] Found {len(results['open_ports'])} open ports")
        except Exception as e:
            print(f"[!] Error during port scanning: {e}")
    
    # Service fingerprinting
    if run_all or "service" in modules:
        if results["open_ports"]:
            print(f"\n[+] Running service fingerprinting for {len(results['open_ports'])} ports")
            try:
                service_results = fingerprint_services(domain, results["open_ports"])
                results["open_ports"] = service_results
                print(f"[+] Completed service fingerprinting")
            except Exception as e:
                print(f"[!] Error during service fingerprinting: {e}")
    
    # Technology stack detection
    if run_all or "tech" in modules:
        print(f"\n[+] Running technology stack detection for {domain}")
        try:
            tech_results = detect_technologies(domain)
            results["tech_stack"] = tech_results.get("technologies", [])
            print(f"[+] Detected {len(results['tech_stack'])} technologies")
        except Exception as e:
            print(f"[!] Error during technology stack detection: {e}")
    
    # SSL/TLS analysis
    if run_all or "ssl" in modules:
        print(f"\n[+] Running SSL/TLS analysis for {domain}")
        try:
            ssl_results = analyze_ssl(domain)
            results["ssl_info"] = ssl_results
            print(f"[+] Completed SSL/TLS analysis: Grade {ssl_results.get('grade', 'Unknown')}")
        except Exception as e:
            print(f"[!] Error during SSL/TLS analysis: {e}")
    
    # HTTP header security audit
    if run_all or "header" in modules:
        print(f"\n[+] Running HTTP header security audit for {domain}")
        try:
            header_results = audit_headers(domain)
            results["headers"] = header_results
            print(f"[+] Completed HTTP header audit: Grade {header_results.get('grade', 'Unknown')}")
        except Exception as e:
            print(f"[!] Error during HTTP header audit: {e}")
    
    # Sensitive path discovery
    if run_all or "path" in modules:
        print(f"\n[+] Running sensitive path discovery for {domain}")
        try:
            path_results = discover_paths(domain, args.wordlist_size)
            results["sensitive_paths"] = path_results.get("discovered_paths", [])
            print(f"[+] Found {len(results['sensitive_paths'])} sensitive paths")
        except Exception as e:
            print(f"[!] Error during sensitive path discovery: {e}")
    
    # OSINT / breach check
    if run_all or "osint" in modules:
        print(f"\n[+] Running OSINT and breach check for {domain}")
        try:
            osint_results = check_breaches(domain)
            results["osint_findings"] = osint_results
            print(f"[+] Found {osint_results.get('breach_count', 0)} breaches and {len(osint_results.get('emails_found', []))} emails")
        except Exception as e:
            print(f"[!] Error during OSINT and breach check: {e}")
    
    elapsed_time = time.time() - start_time
    print(f"\n[+] Scan completed in {elapsed_time:.2f} seconds")
    
    return results


def analyze_results(domain: str, recon_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze reconnaissance data and calculate risk score.
    
    Args:
        domain (str): The domain that was scanned.
        recon_data (Dict[str, Any]): Reconnaissance data.
        
    Returns:
        Dict[str, Any]: Analysis results including risk score and AI analysis.
    """
    print(f"\n[+] Analyzing results for {domain}")
    
    # Calculate risk score
    try:
        risk_data = calculate_risk_score(domain, recon_data)
        print(f"[+] Risk score: {risk_data.get('risk_score', 0)}/100 ({risk_data.get('risk_level', 'Unknown')})")
    except Exception as e:
        print(f"[!] Error calculating risk score: {e}")
        risk_data = {
            "domain": domain,
            "risk_score": 0,
            "risk_level": "Unknown",
            "risk_details": []
        }
    
    # Perform AI analysis
    try:
        ai_analysis = analyze_risks(domain, risk_data)
        print(f"[+] AI analysis completed using {ai_analysis.get('analysis_method', 'Unknown')}")
    except Exception as e:
        print(f"[!] Error during AI analysis: {e}")
        ai_analysis = {
            "domain": domain,
            "summary": "Error during analysis",
            "key_risks": [],
            "recommendations": []
        }
    
    return {
        "risk_data": risk_data,
        "ai_analysis": ai_analysis
    }


def generate_reports(domain: str, recon_data: Dict[str, Any], analysis_results: Dict[str, Any], 
                    output_dir: str, formats: List[str]) -> Dict[str, str]:
    """
    Generate reports in specified formats.
    
    Args:
        domain (str): The domain that was scanned.
        recon_data (Dict[str, Any]): Reconnaissance data.
        analysis_results (Dict[str, Any]): Analysis results.
        output_dir (str): Output directory.
        formats (List[str]): Output formats.
        
    Returns:
        Dict[str, str]: Paths to generated reports.
    """
    print(f"\n[+] Generating reports for {domain}")
    
    risk_data = analysis_results["risk_data"]
    ai_analysis = analysis_results["ai_analysis"]
    
    report_paths = {}
    
    # Generate JSON report
    if "json" in formats:
        json_path = os.path.join(output_dir, f"{domain}_report.json")
        try:
            report = generate_json_report(domain, recon_data, risk_data, ai_analysis, json_path)
            report_paths["json"] = json_path
            print(f"[+] JSON report saved to {json_path}")
        except Exception as e:
            print(f"[!] Error generating JSON report: {e}")
    
    # Generate Markdown report
    if "md" in formats or "markdown" in formats:
        md_path = os.path.join(output_dir, f"{domain}_report.md")
        try:
            # First generate JSON report if not already done
            if "json" not in formats:
                report = generate_json_report(domain, recon_data, risk_data, ai_analysis)
            else:
                with open(report_paths["json"], 'r') as f:
                    report = json.load(f)
            
            markdown = generate_markdown_report(report, md_path)
            report_paths["markdown"] = md_path
            print(f"[+] Markdown report saved to {md_path}")
        except Exception as e:
            print(f"[!] Error generating Markdown report: {e}")
    
    # Generate HTML report
    if "html" in formats:
        html_path = os.path.join(output_dir, f"{domain}_report.html")
        try:
            # First generate JSON report if not already done
            if "json" not in formats:
                report = generate_json_report(domain, recon_data, risk_data, ai_analysis)
            else:
                with open(report_paths["json"], 'r') as f:
                    report = json.load(f)
            
            html = generate_html_report(report, html_path)
            report_paths["html"] = html_path
            print(f"[+] HTML report saved to {html_path}")
        except Exception as e:
            print(f"[!] Error generating HTML report: {e}")
    
    return report_paths


def main():
    """Main function."""
    # Parse arguments
    args = parse_args()
    
    # Print banner
    print_banner()
    
    # Validate arguments
    validate_args(args)
    
    # Get domains to scan
    domains = get_domains(args)
    print(f"[+] Found {len(domains)} domains to scan")
    
    # Get output formats
    formats = args.format.lower().split(",")
    
    # Process each domain
    for domain in domains:
        # Run reconnaissance
        recon_data = scan_domain(domain, args)
        
        # Analyze results
        analysis_results = analyze_results(domain, recon_data)
        
        # Generate reports
        report_paths = generate_reports(
            domain, 
            recon_data, 
            analysis_results, 
            args.output, 
            formats
        )
        
        print(f"\n[+] Completed processing for {domain}")
        for fmt, path in report_paths.items():
            print(f"    - {fmt.upper()} report: {path}")
    
    print("\n[+] All domains processed successfully")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        sys.exit(1)
