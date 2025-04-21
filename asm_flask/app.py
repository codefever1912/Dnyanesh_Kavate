#!/usr/bin/env python3
"""
Main Flask application for the Attack Surface Monitoring Tool.
This file implements the Flask routes and integrates with the ASM tool modules.
"""

from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, session, flash
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, SelectField, SelectMultipleField, SubmitField
from wtforms.validators import DataRequired
import os
import uuid
import json
import shutil
import tempfile
from datetime import datetime
import threading
import csv
import io
import zipfile
import sys

# Add ASM tool modules to path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'asm_tool'))

# Import ASM tool modules
from modules.input.csv_reader import read_domains_from_csv
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
from modules.risk_analysis.risk_scorer import calculate_risk_score
from modules.risk_analysis.ai_analyzer import analyze_risks
from modules.output.json_formatter import generate_json_report
from modules.output.markdown_exporter import generate_markdown_report
from modules.output.html_exporter import generate_html_report

# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Create directories for storing scan data
os.makedirs("data/scans", exist_ok=True)
os.makedirs("data/reports", exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# In-memory storage for active scans
active_scans = {}
completed_scans = []

# Forms
class DomainScanForm(FlaskForm):
    domain = StringField('Domain', validators=[DataRequired()])
    modules = SelectMultipleField('Modules', choices=[
        ('all', 'All Modules'),
        ('subdomain', 'Subdomain Enumeration'),
        ('live', 'Live Subdomain Detection'),
        ('dns', 'WHOIS & DNS Analysis'),
        ('port', 'Port Scanning'),
        ('service', 'Service Fingerprinting'),
        ('tech', 'Technology Stack Detection'),
        ('ssl', 'SSL/TLS Analysis'),
        ('header', 'HTTP Header Security Audit'),
        ('path', 'Sensitive Path Discovery'),
        ('osint', 'OSINT & Breach Check')
    ], default=['all'])
    format = SelectField('Output Format', choices=[
        ('json', 'JSON'),
        ('md', 'Markdown'),
        ('html', 'HTML')
    ], default='html')
    submit = SubmitField('Scan Domain')

class CSVScanForm(FlaskForm):
    csv_file = FileField('CSV File', validators=[
        FileRequired(),
        FileAllowed(['csv'], 'CSV files only!')
    ])
    modules = SelectMultipleField('Modules', choices=[
        ('all', 'All Modules'),
        ('subdomain', 'Subdomain Enumeration'),
        ('live', 'Live Subdomain Detection'),
        ('dns', 'WHOIS & DNS Analysis'),
        ('port', 'Port Scanning'),
        ('service', 'Service Fingerprinting'),
        ('tech', 'Technology Stack Detection'),
        ('ssl', 'SSL/TLS Analysis'),
        ('header', 'HTTP Header Security Audit'),
        ('path', 'Sensitive Path Discovery'),
        ('osint', 'OSINT & Breach Check')
    ], default=['all'])
    format = SelectField('Output Format', choices=[
        ('json', 'JSON'),
        ('md', 'Markdown'),
        ('html', 'HTML')
    ], default='html')
    submit = SubmitField('Upload & Scan')

# Helper functions
def get_risk_class(risk_score):
    """Get CSS class based on risk score."""
    if risk_score >= 85:
        return "critical"
    elif risk_score >= 70:
        return "high"
    elif risk_score >= 50:
        return "medium"
    elif risk_score >= 25:
        return "low"
    else:
        return "info"

def get_module_functions(modules):
    """Get the module functions to run based on selected modules."""
    all_modules = {
        "subdomain": enumerate_subdomains,
        "live": check_live_subdomains,
        "dns": analyze_domain,
        "port": scan_ports,
        "service": fingerprint_services,
        "tech": detect_technologies,
        "ssl": analyze_ssl,
        "header": audit_headers,
        "path": discover_paths,
        "osint": check_breaches
    }
    
    if "all" in modules:
        return all_modules
    
    selected_modules = {}
    for module in modules:
        if module in all_modules:
            selected_modules[module] = all_modules[module]
    
    return selected_modules

def run_scan(scan_id, domain, modules, format):
    """Run a scan in the background."""
    try:
        # Update scan status
        active_scans[scan_id]["status"] = "in_progress"
        active_scans[scan_id]["progress"] = 10
        
        # Get module functions
        module_functions = get_module_functions(modules)
        total_modules = len(module_functions)
        completed_modules = 0
        
        # Create directory for scan results
        scan_dir = os.path.join("data/scans", scan_id)
        os.makedirs(scan_dir, exist_ok=True)
        
        # Initialize recon_data
        recon_data = {"domain": domain}
        
        # Run reconnaissance modules
        for module_name, module_func in module_functions.items():
            try:
                # Update status
                active_scans[scan_id]["current_module"] = module_name
                
                # Run module
                if module_name == "subdomain":
                    recon_data["subdomains"] = module_func(domain)
                elif module_name == "live":
                    if "subdomains" in recon_data:
                        recon_data["live_subdomains"] = module_func(recon_data["subdomains"])
                    else:
                        recon_data["live_subdomains"] = []
                elif module_name == "dns":
                    dns_results = module_func(domain)
                    recon_data["whois"] = dns_results.get("whois", {})
                    recon_data["dns_records"] = dns_results.get("dns_records", {})
                elif module_name == "port":
                    port_results = module_func(domain)
                    recon_data["open_ports"] = port_results.get("open_ports", [])
                elif module_name == "service":
                    if "open_ports" in recon_data:
                        recon_data["services"] = module_func(domain, recon_data["open_ports"])
                    else:
                        recon_data["services"] = []
                elif module_name == "tech":
                    tech_results = module_func(domain)
                    recon_data["tech_stack"] = tech_results.get("technologies", [])
                elif module_name == "ssl":
                    recon_data["ssl_info"] = module_func(domain)
                elif module_name == "header":
                    recon_data["headers"] = module_func(domain)
                elif module_name == "path":
                    path_results = module_func(domain, "small")
                    recon_data["sensitive_paths"] = path_results.get("discovered_paths", [])
                elif module_name == "osint":
                    recon_data["osint_findings"] = module_func(domain)
            except Exception as e:
                print(f"Error in module {module_name}: {str(e)}")
                # Continue with other modules
            
            # Update progress
            completed_modules += 1
            progress = 10 + int((completed_modules / total_modules) * 40)
            active_scans[scan_id]["progress"] = progress
        
        # Calculate risk score
        active_scans[scan_id]["progress"] = 50
        active_scans[scan_id]["current_module"] = "risk_scoring"
        risk_data = calculate_risk_score(domain, recon_data)
        
        # AI analysis
        active_scans[scan_id]["progress"] = 70
        active_scans[scan_id]["current_module"] = "ai_analysis"
        ai_analysis = analyze_risks(domain, risk_data)
        
        # Generate reports
        active_scans[scan_id]["progress"] = 80
        active_scans[scan_id]["current_module"] = "generating_reports"
        
        reports_dir = os.path.join("data/reports", scan_id)
        os.makedirs(reports_dir, exist_ok=True)
        
        # JSON report
        json_path = os.path.join(reports_dir, f"{domain}_report.json")
        json_report = generate_json_report(domain, recon_data, risk_data, ai_analysis, json_path)
        
        # Markdown report
        md_path = os.path.join(reports_dir, f"{domain}_report.md")
        generate_markdown_report(json_report, md_path)
        
        # HTML report
        html_path = os.path.join(reports_dir, f"{domain}_report.html")
        generate_html_report(json_report, html_path)
        
        # Create ZIP archive of all reports
        zip_path = os.path.join(reports_dir, f"{domain}_reports.zip")
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            zipf.write(json_path, os.path.basename(json_path))
            zipf.write(md_path, os.path.basename(md_path))
            zipf.write(html_path, os.path.basename(html_path))
        
        # Update scan status
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["progress"] = 100
        active_scans[scan_id]["end_time"] = datetime.now().isoformat()
        active_scans[scan_id]["risk_score"] = risk_data.get("risk_score", 0)
        active_scans[scan_id]["risk_level"] = risk_data.get("risk_level", "Unknown")
        
        # Add to completed scans
        completed_scans.append({
            "id": scan_id,
            "domain": domain,
            "date": active_scans[scan_id]["start_time"],
            "risk_score": risk_data.get("risk_score", 0),
            "risk_level": risk_data.get("risk_level", "Unknown"),
            "risk_class": get_risk_class(risk_data.get("risk_score", 0)),
            "status": "completed"
        })
        
        # Save scan data to file
        with open(os.path.join(scan_dir, "scan_data.json"), "w") as f:
            json.dump(active_scans[scan_id], f)
        
    except Exception as e:
        # Update scan status on error
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)
        active_scans[scan_id]["end_time"] = datetime.now().isoformat()
        print(f"Error in scan {scan_id}: {str(e)}")

# Routes
@app.route('/')
def home():
    """Home page."""
    domain_form = DomainScanForm()
    csv_form = CSVScanForm()
    
    # Get recent scans (up to 5)
    recent_scans = []
    for scan in completed_scans[-5:]:
        recent_scans.append({
            "domain": scan["domain"],
            "date": scan["date"],
            "risk_score": scan["risk_score"],
            "risk_class": scan["risk_class"],
            "report_url": f"/reports/{scan['id']}/html"
        })
    
    return render_template('index.html', 
                          domain_form=domain_form, 
                          csv_form=csv_form, 
                          scans=recent_scans)

@app.route('/dashboard')
def dashboard():
    """Dashboard page."""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', None)
    
    # Filter scans by search term
    filtered_scans = []
    if search:
        search = search.lower()
        for scan in completed_scans:
            if search in scan["domain"].lower():
                filtered_scans.append(scan)
    else:
        filtered_scans = completed_scans.copy()
    
    # Add in-progress scans
    for scan_id, scan_data in active_scans.items():
        if scan_data["status"] != "completed" and scan_data["status"] != "failed":
            filtered_scans.append({
                "id": scan_id,
                "domain": scan_data["domain"],
                "date": scan_data["start_time"],
                "status": scan_data["status"]
            })
    
    # Sort by date (newest first)
    filtered_scans.sort(key=lambda x: x.get("date", ""), reverse=True)
    
    # Pagination
    items_per_page = 10
    total_pages = max(1, (len(filtered_scans) + items_per_page - 1) // items_per_page)
    page = min(max(1, page), total_pages)
    
    start_idx = (page - 1) * items_per_page
    end_idx = min(start_idx + items_per_page, len(filtered_scans))
    
    page_scans = filtered_scans[start_idx:end_idx]
    
    return render_template('dashboard.html', 
                          scans=page_scans,
                          page=page,
                          total_pages=total_pages,
                          search=search)

@app.route('/documentation')
def documentation():
    """Documentation page."""
    return render_template('documentation.html')

@app.route('/about')
def about():
    """About page."""
    return render_template('about.html')

@app.route('/status/<scan_id>')
def status_page(scan_id):
    """Status page for a scan."""
    if scan_id not in active_scans:
        flash('Scan not found', 'error')
        return redirect(url_for('home'))
    
    scan_data = active_scans[scan_id]
    
    return render_template('status.html', 
                          scan_id=scan_id,
                          domain=scan_data["domain"],
                          status=scan_data["status"],
                          progress=scan_data["progress"])

@app.route('/scan/domain', methods=['POST'])
def scan_domain():
    """Scan a single domain."""
    form = DomainScanForm()
    
    if form.validate_on_submit():
        domain = form.domain.data
        modules = form.modules.data
        format = form.format.data
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Initialize scan data
        active_scans[scan_id] = {
            "domain": domain,
            "modules": modules,
            "format": format,
            "status": "queued",
            "progress": 0,
            "start_time": datetime.now().isoformat(),
            "current_module": "initializing"
        }
        
        # Start scan in background
        scan_thread = threading.Thread(target=run_scan, args=(scan_id, domain, modules, format))
        scan_thread.daemon = True
        scan_thread.start()
        
        flash(f'Scan started for domain: {domain}', 'success')
        return redirect(url_for('status_page', scan_id=scan_id))
    
    flash('Invalid form submission', 'error')
    return redirect(url_for('home'))

@app.route('/scan/csv', methods=['POST'])
def scan_csv():
    """Scan domains from a CSV file."""
    form = CSVScanForm()
    
    if form.validate_on_submit():
        # Save uploaded file
        csv_file = form.csv_file.data
        filename = str(uuid.uuid4()) + '.csv'
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        csv_file.save(filepath)
        
        # Parse modules and format
        modules = form.modules.data
        format = form.format.data
        
        # Parse CSV
        try:
            domains = []
            with open(filepath, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if 'domain' in row:
                        domains.append(row['domain'])
            
            if not domains:
                flash('No domains found in CSV file', 'error')
                return redirect(url_for('home'))
            
            # Generate scan ID
            scan_id = str(uuid.uuid4())
            
            # Initialize scan data
            active_scans[scan_id] = {
                "domain": f"CSV ({len(domains)} domains)",
                "domains": domains,
                "modules": modules,
                "format": format,
                "status": "queued",
                "progress": 0,
                "start_time": datetime.now().isoformat(),
                "current_module": "initializing"
            }
            
            # Start scan for first domain in background
            scan_thread = threading.Thread(target=run_scan, args=(scan_id, domains[0], modules, format))
            scan_thread.daemon = True
            scan_thread.start()
            
            flash(f'Scan started for {len(domains)} domains', 'success')
            return redirect(url_for('status_page', scan_id=scan_id))
            
        except Exception as e:
            flash(f'Error parsing CSV file: {str(e)}', 'error')
            return redirect(url_for('home'))
    
    flash('Invalid form submission', 'error')
    return redirect(url_for('home'))

@app.route('/api/status/<scan_id>')
def get_status(scan_id):
    """Get the status of a scan."""
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404
    
    scan_data = active_scans[scan_id]
    
    return jsonify({
        "scan_id": scan_id,
        "domain": scan_data["domain"],
        "status": scan_data["status"],
        "progress": scan_data["progress"],
        "start_time": scan_data["start_time"],
        "end_time": scan_data.get("end_time"),
        "current_module": scan_data.get("current_module"),
        "error": scan_data.get("error")
    })

@app.route('/reports/<scan_id>/<format>')
def get_report(scan_id, format):
    """Get a report in the specified format."""
    if scan_id not in active_scans:
        flash('Scan not found', 'error')
        return redirect(url_for('home'))
    
    scan_data = active_scans[scan_id]
    
    if scan_data["status"] != "completed":
        flash('Scan not completed', 'error')
        return redirect(url_for('status_page', scan_id=scan_id))
    
    domain = scan_data["domain"]
    reports_dir = os.path.join("data/reports", scan_id)
    
    if format == "json":
        return send_file(
            os.path.join(reports_dir, f"{domain}_report.json"),
            mimetype="application/json",
            as_attachment=True,
            download_name=f"{domain}_report.json"
        )
    elif format == "md":
        return send_file(
            os.path.join(reports_dir, f"{domain}_report.md"),
            mimetype="text/markdown",
            as_attachment=True,
            download_name=f"{domain}_report.md"
        )
    elif format == "html":
        return send_file(
            os.path.join(reports_dir, f"{domain}_report.html"),
            mimetype="text/html",
            as_attachment=False
        )
    else:
        flash('Invalid format', 'error')
        return redirect(url_for('status_page', scan_id=scan_id))

@app.route('/download/<scan_id>')
def download_reports(scan_id):
    """Download all reports as a ZIP file."""
    if scan_id not in active_scans:
        flash('Scan not found', 'error')
        return redirect(url_for('home'))
    
    scan_data = active_scans[scan_id]
    
    if scan_data["status"] != "completed":
        flash('Scan not completed', 'error')
        return redirect(url_for('status_page', scan_id=scan_id))
    
    domain = scan_data["domain"]
    reports_dir = os.path.join("data/reports", scan_id)
    zip_path = os.path.join(reports_dir, f"{domain}_reports.zip")
    
    return send_file(
        zip_path,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"{domain}_reports.zip"
    )

@app.route('/api/delete-scan/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan."""
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404
    
    # Remove from active_scans
    scan_data = active_scans.pop(scan_id)
    
    # Remove from completed_scans
    global completed_scans
    completed_scans = [scan for scan in completed_scans if scan.get("id") != scan_id]
    
    # Delete scan directory
    scan_dir = os.path.join("data/scans", scan_id)
    if os.path.exists(scan_dir):
        shutil.rmtree(scan_dir)
    
    # Delete reports directory
    reports_dir = os.path.join("data/reports", scan_id)
    if os.path.exists(reports_dir):
        shutil.rmtree(reports_dir)
    
    return jsonify({"success": True, "message": "Scan deleted"})

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

# Load sample data for development
def load_sample_data():
    """Load sample data for development."""
    # Add a sample completed scan
    sample_scan_id = str(uuid.uuid4())
    sample_domain = "example.com"
    sample_date = datetime.now().isoformat()
    
    active_scans[sample_scan_id] = {
        "domain": sample_domain,
        "modules": ["all"],
        "format": "html",
        "status": "completed",
        "progress": 100,
        "start_time": sample_date,
        "end_time": sample_date,
        "risk_score": 65,
        "risk_level": "Medium"
    }
    
    completed_scans.append({
        "id": sample_scan_id,
        "domain": sample_domain,
        "date": sample_date,
        "risk_score": 65,
        "risk_level": "Medium",
        "risk_class": "medium",
        "status": "completed"
    })

if __name__ == '__main__':
    # Load sample data in development mode
    if app.debug:
        load_sample_data()
    
    app.run(host='0.0.0.0', port=8000, debug=True)
