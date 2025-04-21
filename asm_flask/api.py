#!/usr/bin/env python3
"""
API Endpoint for Attack Surface Monitoring Tool
This module provides a FastAPI interface for the ASM tool.
"""

import os
import sys
import json
import time
import uuid
import shutil
from typing import List, Dict, Any, Optional
from datetime import datetime
from fastapi import FastAPI, File, UploadFile, Form, BackgroundTasks, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
import uvicorn
import csv
from io import StringIO

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

# Create FastAPI app
app = FastAPI(
    title="Attack Surface Monitoring Tool API",
    description="API for scanning and analyzing domain attack surfaces",
    version="1.0.0",
)

# Create output directory if it doesn't exist
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Create templates directory and static files directory
TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
os.makedirs(TEMPLATES_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# Initialize templates
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Create HTML templates
def create_templates():
    """Create HTML templates for the web interface."""
    index_html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Attack Surface Monitoring Tool</title>
        <link rel="stylesheet" href="/static/styles.css">
    </head>
    <body>
        <header>
            <h1>Attack Surface Monitoring Tool</h1>
        </header>
        <main>
            <div class="container">
                <div class="card">
                    <h2>Scan Domain</h2>
                    <form id="domain-form" action="/scan/domain" method="post">
                        <div class="form-group">
                            <label for="domain">Domain:</label>
                            <input type="text" id="domain" name="domain" placeholder="example.com" required>
                        </div>
                        <div class="form-group">
                            <label for="modules">Modules:</label>
                            <select id="modules" name="modules" multiple>
                                <option value="all" selected>All Modules</option>
                                <option value="subdomain">Subdomain Enumeration</option>
                                <option value="live">Live Subdomain Detection</option>
                                <option value="dns">WHOIS & DNS Analysis</option>
                                <option value="port">Port Scanning</option>
                                <option value="service">Service Fingerprinting</option>
                                <option value="tech">Technology Stack Detection</option>
                                <option value="ssl">SSL/TLS Analysis</option>
                                <option value="header">HTTP Header Security Audit</option>
                                <option value="path">Sensitive Path Discovery</option>
                                <option value="osint">OSINT & Breach Check</option>
                            </select>
                            <small>Hold Ctrl/Cmd to select multiple modules</small>
                        </div>
                        <div class="form-group">
                            <label for="format">Output Format:</label>
                            <select id="format" name="format">
                                <option value="json">JSON</option>
                                <option value="md">Markdown</option>
                                <option value="html" selected>HTML</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <button type="submit">Scan Domain</button>
                        </div>
                    </form>
                </div>

                <div class="card">
                    <h2>Upload CSV File</h2>
                    <form id="csv-form" action="/scan/csv" method="post" enctype="multipart/form-data">
                        <div class="form-group">
                            <label for="csv_file">CSV File:</label>
                            <input type="file" id="csv_file" name="csv_file" accept=".csv" required>
                            <small>CSV file with a 'domain' column</small>
                        </div>
                        <div class="form-group">
                            <label for="csv_modules">Modules:</label>
                            <select id="csv_modules" name="modules" multiple>
                                <option value="all" selected>All Modules</option>
                                <option value="subdomain">Subdomain Enumeration</option>
                                <option value="live">Live Subdomain Detection</option>
                                <option value="dns">WHOIS & DNS Analysis</option>
                                <option value="port">Port Scanning</option>
                                <option value="service">Service Fingerprinting</option>
                                <option value="tech">Technology Stack Detection</option>
                                <option value="ssl">SSL/TLS Analysis</option>
                                <option value="header">HTTP Header Security Audit</option>
                                <option value="path">Sensitive Path Discovery</option>
                                <option value="osint">OSINT & Breach Check</option>
                            </select>
                            <small>Hold Ctrl/Cmd to select multiple modules</small>
                        </div>
                        <div class="form-group">
                            <label for="csv_format">Output Format:</label>
                            <select id="csv_format" name="format">
                                <option value="json">JSON</option>
                                <option value="md">Markdown</option>
                                <option value="html" selected>HTML</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <button type="submit">Upload & Scan</button>
                        </div>
                    </form>
                </div>

                <div class="card">
                    <h2>Recent Scans</h2>
                    <div id="recent-scans">
                        {% if scans %}
                            <table>
                                <thead>
                                    <tr>
                                        <th>Domain</th>
                                        <th>Date</th>
                                        <th>Risk Score</th>
                                        <th>Report</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for scan in scans %}
                                    <tr>
                                        <td>{{ scan.domain }}</td>
                                        <td>{{ scan.date }}</td>
                                        <td class="{{ scan.risk_class }}">{{ scan.risk_score }}/100</td>
                                        <td><a href="{{ scan.report_url }}">View Report</a></td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        {% else %}
                            <p>No scans yet. Start by scanning a domain or uploading a CSV file.</p>
                        {% endif %}
                    </div>
                </div>
            </div>
        </main>
        <footer>
            <p>Attack Surface Monitoring Tool &copy; 2025</p>
        </footer>
        <script src="/static/script.js"></script>
    </body>
    </html>
    """

    status_html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Scan Status - Attack Surface Monitoring Tool</title>
        <link rel="stylesheet" href="/static/styles.css">
        <meta http-equiv="refresh" content="5;url=/status/{{ scan_id }}">
    </head>
    <body>
        <header>
            <h1>Attack Surface Monitoring Tool</h1>
        </header>
        <main>
            <div class="container">
                <div class="card">
                    <h2>Scan Status</h2>
                    <div class="status-container">
                        <h3>Domain: {{ domain }}</h3>
                        <p><strong>Status:</strong> {{ status }}</p>
                        <p><strong>Progress:</strong> {{ progress }}%</p>
                        <div class="progress-bar">
                            <div class="progress" style="width: {{ progress }}%"></div>
                        </div>
                        <p><strong>Current Step:</strong> {{ current_step }}</p>
                        
                        {% if status == "completed" %}
                            <div class="result-links">
                                <h4>Scan Results:</h4>
                                <ul>
                                    {% for format, url in report_urls.items() %}
                                    <li><a href="{{ url }}" target="_blank">{{ format|upper }} Report</a></li>
                                    {% endfor %}
                                </ul>
                            </div>
                        {% endif %}
                        
                        <div class="buttons">
                            <a href="/" class="button">Back to Home</a>
                            {% if status == "completed" %}
                            <a href="/download/{{ scan_id }}" class="button">Download All Reports</a>
                            {% endif %}
                        </div>
                    </div>
                </div>
            </div>
        </main>
        <footer>
            <p>Attack Surface Monitoring Tool &copy; 2025</p>
        </footer>
        <script>
            {% if status != "completed" and status != "failed" %}
            // Auto-refresh every 5 seconds if scan is still in progress
            setTimeout(function() {
                window.location.reload();
            }, 5000);
            {% endif %}
        </script>
    </body>
    </html>
    """

    # Write templates to files
    with open(os.path.join(TEMPLATES_DIR, "index.html"), "w") as f:
        f.write(index_html)
    
    with open(os.path.join(TEMPLATES_DIR, "status.html"), "w") as f:
        f.write(status_html)

    # Create CSS file
    css = """
    :root {
        --primary-color: #2c3e50;
        --secondary-color: #3498db;
        --accent-color: #e74c3c;
        --success-color: #2ecc71;
        --warning-color: #f39c12;
        --error-color: #e74c3c;
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
    
    main {
        padding: 2rem;
    }
    
    .container {
        max-width: 1200px;
        margin: 0 auto;
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
        gap: 2rem;
    }
    
    .card {
        background-color: white;
        border-radius: 5px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        padding: 1.5rem;
        overflow: hidden;
    }
    
    h2 {
        color: var(--primary-color);
        margin-bottom: 1.5rem;
        border-bottom: 2px solid var(--secondary-color);
        padding-bottom: 0.5rem;
    }
    
    .form-group {
        margin-bottom: 1.5rem;
    }
    
    label {
        display: block;
        margin-bottom: 0.5rem;
        font-weight: bold;
    }
    
    input[type="text"],
    input[type="file"],
    select {
        width: 100%;
        padding: 0.75rem;
        border: 1px solid var(--border-color);
        border-radius: 4px;
        font-size: 1rem;
    }
    
    select[multiple] {
        height: 150px;
    }
    
    small {
        display: block;
        margin-top: 0.25rem;
        color: #666;
    }
    
    button {
        background-color: var(--secondary-color);
        color: white;
        border: none;
        padding: 0.75rem 1.5rem;
        border-radius: 4px;
        cursor: pointer;
        font-size: 1rem;
        transition: background-color 0.3s;
    }
    
    button:hover {
        background-color: #2980b9;
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
    
    a {
        color: var(--secondary-color);
        text-decoration: none;
    }
    
    a:hover {
        text-decoration: underline;
    }
    
    .critical {
        color: var(--error-color);
        font-weight: bold;
    }
    
    .high {
        color: #ff6b6b;
        font-weight: bold;
    }
    
    .medium {
        color: var(--warning-color);
    }
    
    .low {
        color: #74b9ff;
    }
    
    .info {
        color: #a29bfe;
    }
    
    .status-container {
        text-align: center;
    }
    
    .progress-bar {
        width: 100%;
        height: 20px;
        background-color: #eee;
        border-radius: 10px;
        margin: 1rem 0;
        overflow: hidden;
    }
    
    .progress {
        height: 100%;
        background-color: var(--secondary-color);
        transition: width 0.5s;
    }
    
    .result-links {
        margin: 1.5rem 0;
        text-align: left;
    }
    
    .result-links ul {
        list-style: none;
        margin-top: 0.5rem;
    }
    
    .result-links li {
        margin-bottom: 0.5rem;
    }
    
    .buttons {
        margin-top: 1.5rem;
        display: flex;
        justify-content: center;
        gap: 1rem;
    }
    
    .button {
        display: inline-block;
        background-color: var(--secondary-color);
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 4px;
        text-decoration: none;
    }
    
    .button:hover {
        background-color: #2980b9;
        text-decoration: none;
    }
    
    footer {
        background-color: var(--primary-color);
        color: white;
        text-align: center;
        padding: 1rem;
        margin-top: 2rem;
    }
    
    @media (max-width: 768px) {
        .container {
            grid-template-columns: 1fr;
        }
    }
    """
    
    with open(os.path.join(STATIC_DIR, "styles.css"), "w") as f:
        f.write(css)
    
    # Create JavaScript file
    js = """
    document.addEventListener('DOMContentLoaded', function() {
        // Handle domain form submission
        const domainForm = document.getElementById('domain-form');
        if (domainForm) {
            domainForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const domain = document.getElementById('domain').value;
                if (!domain) {
                    alert('Please enter a domain');
                    return;
                }
                
                const modulesSelect = document.getElementById('modules');
                const selectedModules = Array.from(modulesSelect.selectedOptions).map(option => option.value);
                
                const format = document.getElementById('format').value;
                
                // Create form data
                const formData = new FormData();
                formData.append('domain', domain);
                formData.append('modules', selectedModules.join(','));
                formData.append('format', format);
                
                // Show loading indicator
                domainForm.innerHTML = '<div class="loading">Scanning domain... Please wait.</div>';
                
                // Submit form
                fetch('/scan/domain', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.scan_id) {
                        window.location.href = `/status/${data.scan_id}`;
                    } else {
                        alert('Error: ' + data.detail);
                        window.location.reload();
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error occurred. Please try again.');
                    window.location.reload();
                });
            });
        }
        
        // Handle CSV form submission
        const csvForm = document.getElementById('csv-form');
        if (csvForm) {
            csvForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const csvFile = document.getElementById('csv_file').files[0];
                if (!csvFile) {
                    alert('Please select a CSV file');
                    return;
                }
                
                const modulesSelect = document.getElementById('csv_modules');
                const selectedModules = Array.from(modulesSelect.selectedOptions).map(option => option.value);
                
                const format = document.getElementById('csv_format').value;
                
                // Create form data
                const formData = new FormData();
                formData.append('csv_file', csvFile);
                formData.append('modules', selectedModules.join(','));
                formData.append('format', format);
                
                // Show loading indicator
                csvForm.innerHTML = '<div class="loading">Uploading and scanning... Please wait.</div>';
                
                // Submit form
                fetch('/scan/csv', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.scan_id) {
                        window.location.href = `/status/${data.scan_id}`;
                    } else {
                        alert('Error: ' + data.detail);
                        window.location.reload();
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error occurred. Please try again.');
                    window.location.reload();
                });
            });
        }
    });
    """
    
    with open(os.path.join(STATIC_DIR, "script.js"), "w") as f:
        f.write(js)

# Create templates when the module is imported
create_templates()

# Define models
class DomainScanRequest(BaseModel):
    domain: str = Field(..., description="Domain to scan")
    modules: str = Field("all", description="Modules to run, comma-separated")
    format: str = Field("json", description="Output format (json, md, html)")

class ScanStatus(BaseModel):
    scan_id: str
    domain: str
    status: str
    progress: int
    current_step: str
    result: Optional[Dict[str, Any]] = None
    report_urls: Optional[Dict[str, str]] = None

# Store scan statuses
scan_statuses = {}

# Store recent scans for the web interface
recent_scans = []

@app.get("/", response_class=HTMLResponse)
async def get_index(request: Request):
    """Render the index page."""
    # Prepare recent scans data for the template
    scans_data = []
    for scan in recent_scans[:10]:  # Show only the 10 most recent scans
        risk_score = scan.get("risk_score", 0)
        risk_class = "info"
        if risk_score >= 85:
            risk_class = "critical"
        elif risk_score >= 70:
            risk_class = "high"
        elif risk_score >= 50:
            risk_class = "medium"
        elif risk_score >= 25:
            risk_class = "low"
        
        scans_data.append({
            "domain": scan.get("domain", "Unknown"),
            "date": scan.get("scan_date", "Unknown"),
            "risk_score": risk_score,
            "risk_class": risk_class,
            "report_url": f"/reports/{scan.get('scan_id', '')}/html"
        })
    
    return templates.TemplateResponse("index.html", {"request": request, "scans": scans_data})

@app.get("/status/{scan_id}", response_class=HTMLResponse)
async def get_scan_status_page(scan_id: str, request: Request):
    """Render the scan status page."""
    if scan_id not in scan_statuses:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    status = scan_statuses[scan_id]
    
    # Prepare report URLs if scan is completed
    report_urls = {}
    if status["status"] == "completed" and status["report_urls"]:
        report_urls = status["report_urls"]
    
    return templates.TemplateResponse(
        "status.html", 
        {
            "request": request, 
            "scan_id": scan_id,
            "domain": status["domain"],
            "status": status["status"],
            "progress": status["progress"],
            "current_step": status["current_step"],
            "report_urls": report_urls
        }
    )

@app.post("/scan/domain")
async def scan_domain(
    background_tasks: BackgroundTasks,
    domain: str = Form(...),
    modules: str = Form("all"),
    format: str = Form("json")
):
    """
    Scan a single domain.
    
    Args:
        domain: The domain to scan.
        modules: Modules to run, comma-separated.
        format: Output format (json, md, html).
    
    Returns:
        JSON response with scan ID.
    """
    # Validate domain
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Invalid domain")
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())
    
    # Create scan directory
    scan_dir = os.path.join(OUTPUT_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)
    
    # Initialize scan status
    scan_statuses[scan_id] = {
        "scan_id": scan_id,
        "domain": domain,
        "status": "queued",
        "progress": 0,
        "current_step": "Initializing...",
        "result": None,
        "report_urls": None
    }
    
    # Start scan in background
    background_tasks.add_task(
        run_scan,
        scan_id,
        [domain],
        modules,
        format,
        scan_dir
    )
    
    return {"scan_id": scan_id}

@app.post("/scan/csv")
async def scan_csv(
    background_tasks: BackgroundTasks,
    csv_file: UploadFile = File(...),
    modules: str = Form("all"),
    format: str = Form("json")
):
    """
    Scan domains from a CSV file.
    
    Args:
        csv_file: CSV file with domains.
        modules: Modules to run, comma-separated.
        format: Output format (json, md, html).
    
    Returns:
        JSON response with scan ID.
    """
    # Validate file
    if not csv_file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="File must be a CSV")
    
    # Read domains from CSV
    content = await csv_file.read()
    content_str = content.decode("utf-8")
    
    # Parse CSV
    domains = []
    try:
        csv_reader = csv.DictReader(StringIO(content_str))
        for row in csv_reader:
            if "domain" in row and row["domain"]:
                domains.append(row["domain"])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error parsing CSV: {str(e)}")
    
    if not domains:
        raise HTTPException(status_code=400, detail="No domains found in CSV")
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())
    
    # Create scan directory
    scan_dir = os.path.join(OUTPUT_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)
    
    # Initialize scan status
    scan_statuses[scan_id] = {
        "scan_id": scan_id,
        "domain": f"{len(domains)} domains from CSV",
        "status": "queued",
        "progress": 0,
        "current_step": "Initializing...",
        "result": None,
        "report_urls": None
    }
    
    # Start scan in background
    background_tasks.add_task(
        run_scan,
        scan_id,
        domains,
        modules,
        format,
        scan_dir
    )
    
    return {"scan_id": scan_id}

@app.get("/api/status/{scan_id}")
async def get_scan_status(scan_id: str):
    """
    Get the status of a scan.
    
    Args:
        scan_id: The scan ID.
    
    Returns:
        JSON response with scan status.
    """
    if scan_id not in scan_statuses:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_statuses[scan_id]

@app.get("/reports/{scan_id}/{format}")
async def get_report(scan_id: str, format: str):
    """
    Get a report.
    
    Args:
        scan_id: The scan ID.
        format: The report format (json, md, html).
    
    Returns:
        The report file.
    """
    if scan_id not in scan_statuses:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    status = scan_statuses[scan_id]
    if status["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed")
    
    if not status["report_urls"] or format not in status["report_urls"]:
        raise HTTPException(status_code=404, detail=f"Report in {format} format not found")
    
    report_path = status["report_urls"][format].replace("/reports/", OUTPUT_DIR + "/")
    
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report file not found")
    
    return FileResponse(
        report_path,
        media_type=get_media_type(format),
        filename=os.path.basename(report_path)
    )

@app.get("/download/{scan_id}")
async def download_all_reports(scan_id: str):
    """
    Download all reports for a scan as a ZIP file.
    
    Args:
        scan_id: The scan ID.
    
    Returns:
        ZIP file with all reports.
    """
    if scan_id not in scan_statuses:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    status = scan_statuses[scan_id]
    if status["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed")
    
    # Create ZIP file
    zip_path = os.path.join(OUTPUT_DIR, f"{scan_id}.zip")
    scan_dir = os.path.join(OUTPUT_DIR, scan_id)
    
    try:
        shutil.make_archive(zip_path[:-4], 'zip', scan_dir)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating ZIP file: {str(e)}")
    
    return FileResponse(
        zip_path,
        media_type="application/zip",
        filename=f"asm_reports_{status['domain'].replace('.', '_')}.zip"
    )

def get_media_type(format: str) -> str:
    """Get the media type for a report format."""
    if format == "json":
        return "application/json"
    elif format == "md":
        return "text/markdown"
    elif format == "html":
        return "text/html"
    else:
        return "text/plain"

async def run_scan(scan_id: str, domains: List[str], modules: str, format: str, output_dir: str):
    """
    Run a scan in the background.
    
    Args:
        scan_id: The scan ID.
        domains: List of domains to scan.
        modules: Modules to run, comma-separated.
        format: Output format (json, md, html).
        output_dir: Output directory.
    """
    try:
        # Update status
        scan_statuses[scan_id]["status"] = "running"
        scan_statuses[scan_id]["current_step"] = "Starting scan..."
        
        # Parse modules and format
        modules_list = modules.split(",")
        formats_list = format.split(",")
        
        # Ensure at least one format is specified
        if not formats_list:
            formats_list = ["json"]
        
        # Scan each domain
        total_domains = len(domains)
        domain_results = []
        
        for i, domain in enumerate(domains):
            # Update status
            domain_progress = (i / total_domains) * 100
            scan_statuses[scan_id]["progress"] = int(domain_progress)
            scan_statuses[scan_id]["current_step"] = f"Scanning domain {i+1}/{total_domains}: {domain}"
            
            # Run reconnaissance
            recon_data = await scan_single_domain(scan_id, domain, modules_list, i, total_domains)
            
            # Analyze results
            analysis_results = await analyze_domain_results(scan_id, domain, recon_data, i, total_domains)
            
            # Generate reports
            report_paths = await generate_domain_reports(
                scan_id,
                domain,
                recon_data,
                analysis_results,
                formats_list,
                output_dir,
                i,
                total_domains
            )
            
            # Store domain result
            domain_result = {
                "domain": domain,
                "scan_date": datetime.now().strftime("%Y-%m-%d"),
                "risk_score": analysis_results["risk_data"].get("risk_score", 0),
                "risk_level": analysis_results["risk_data"].get("risk_level", "Unknown"),
                "report_paths": report_paths,
                "scan_id": scan_id
            }
            
            domain_results.append(domain_result)
            
            # Add to recent scans
            recent_scans.insert(0, domain_result)
            if len(recent_scans) > 20:
                recent_scans.pop()
        
        # Update status
        scan_statuses[scan_id]["status"] = "completed"
        scan_statuses[scan_id]["progress"] = 100
        scan_statuses[scan_id]["current_step"] = "Scan completed"
        scan_statuses[scan_id]["result"] = domain_results
        
        # Create report URLs
        report_urls = {}
        for domain_result in domain_results:
            for format_type, path in domain_result["report_paths"].items():
                # Convert local path to URL
                url = path.replace(output_dir, f"/reports/{scan_id}")
                
                # Add to report URLs
                if format_type not in report_urls:
                    report_urls[format_type] = []
                
                report_urls[format_type] = url
        
        scan_statuses[scan_id]["report_urls"] = report_urls
    
    except Exception as e:
        # Update status on error
        scan_statuses[scan_id]["status"] = "failed"
        scan_statuses[scan_id]["current_step"] = f"Error: {str(e)}"
        print(f"Error during scan: {str(e)}")

async def scan_single_domain(scan_id: str, domain: str, modules: List[str], domain_index: int, total_domains: int) -> Dict[str, Any]:
    """
    Scan a single domain with all or selected modules.
    
    Args:
        scan_id: The scan ID.
        domain: The domain to scan.
        modules: List of modules to run.
        domain_index: Index of the current domain.
        total_domains: Total number of domains.
        
    Returns:
        Dict[str, Any]: Reconnaissance data.
    """
    # Calculate base progress for this domain
    base_progress = (domain_index / total_domains) * 100
    progress_per_module = 10 / len(modules) if modules else 10
    
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
    
    run_all = "all" in modules
    module_index = 0
    
    # Subdomain enumeration
    if run_all or "subdomain" in modules:
        scan_statuses[scan_id]["current_step"] = f"Running subdomain enumeration for {domain}"
        scan_statuses[scan_id]["progress"] = int(base_progress + (module_index * progress_per_module))
        module_index += 1
        
        try:
            subdomains = enumerate_subdomains(domain)
            results["subdomains"] = subdomains
        except Exception as e:
            print(f"Error during subdomain enumeration: {str(e)}")
    
    # Live subdomain detection
    if (run_all or "live" in modules) and results["subdomains"]:
        scan_statuses[scan_id]["current_step"] = f"Running live subdomain detection for {domain}"
        scan_statuses[scan_id]["progress"] = int(base_progress + (module_index * progress_per_module))
        module_index += 1
        
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
        except Exception as e:
            print(f"Error during live subdomain detection: {str(e)}")
    
    # WHOIS & DNS records
    if run_all or "dns" in modules:
        scan_statuses[scan_id]["current_step"] = f"Running WHOIS & DNS analysis for {domain}"
        scan_statuses[scan_id]["progress"] = int(base_progress + (module_index * progress_per_module))
        module_index += 1
        
        try:
            dns_results = analyze_whois_dns(domain)
            results["whois"] = dns_results.get("whois", {})
            results["dns_records"] = dns_results.get("dns_records", {})
        except Exception as e:
            print(f"Error during WHOIS & DNS analysis: {str(e)}")
    
    # Port scanning
    if run_all or "port" in modules:
        scan_statuses[scan_id]["current_step"] = f"Running port scan for {domain}"
        scan_statuses[scan_id]["progress"] = int(base_progress + (module_index * progress_per_module))
        module_index += 1
        
        try:
            port_results = scan_ports(domain)
            results["open_ports"] = port_results.get("open_ports", [])
        except Exception as e:
            print(f"Error during port scanning: {str(e)}")
    
    # Service fingerprinting
    if (run_all or "service" in modules) and results["open_ports"]:
        scan_statuses[scan_id]["current_step"] = f"Running service fingerprinting for {domain}"
        scan_statuses[scan_id]["progress"] = int(base_progress + (module_index * progress_per_module))
        module_index += 1
        
        try:
            service_results = fingerprint_services(domain, results["open_ports"])
            results["open_ports"] = service_results
        except Exception as e:
            print(f"Error during service fingerprinting: {str(e)}")
    
    # Technology stack detection
    if run_all or "tech" in modules:
        scan_statuses[scan_id]["current_step"] = f"Running technology stack detection for {domain}"
        scan_statuses[scan_id]["progress"] = int(base_progress + (module_index * progress_per_module))
        module_index += 1
        
        try:
            tech_results = detect_technologies(domain)
            results["tech_stack"] = tech_results.get("technologies", [])
        except Exception as e:
            print(f"Error during technology stack detection: {str(e)}")
    
    # SSL/TLS analysis
    if run_all or "ssl" in modules:
        scan_statuses[scan_id]["current_step"] = f"Running SSL/TLS analysis for {domain}"
        scan_statuses[scan_id]["progress"] = int(base_progress + (module_index * progress_per_module))
        module_index += 1
        
        try:
            ssl_results = analyze_ssl(domain)
            results["ssl_info"] = ssl_results
        except Exception as e:
            print(f"Error during SSL/TLS analysis: {str(e)}")
    
    # HTTP header security audit
    if run_all or "header" in modules:
        scan_statuses[scan_id]["current_step"] = f"Running HTTP header security audit for {domain}"
        scan_statuses[scan_id]["progress"] = int(base_progress + (module_index * progress_per_module))
        module_index += 1
        
        try:
            header_results = audit_headers(domain)
            results["headers"] = header_results
        except Exception as e:
            print(f"Error during HTTP header audit: {str(e)}")
    
    # Sensitive path discovery
    if run_all or "path" in modules:
        scan_statuses[scan_id]["current_step"] = f"Running sensitive path discovery for {domain}"
        scan_statuses[scan_id]["progress"] = int(base_progress + (module_index * progress_per_module))
        module_index += 1
        
        try:
            path_results = discover_paths(domain)
            results["sensitive_paths"] = path_results.get("discovered_paths", [])
        except Exception as e:
            print(f"Error during sensitive path discovery: {str(e)}")
    
    # OSINT / breach check
    if run_all or "osint" in modules:
        scan_statuses[scan_id]["current_step"] = f"Running OSINT and breach check for {domain}"
        scan_statuses[scan_id]["progress"] = int(base_progress + (module_index * progress_per_module))
        module_index += 1
        
        try:
            osint_results = check_breaches(domain)
            results["osint_findings"] = osint_results
        except Exception as e:
            print(f"Error during OSINT and breach check: {str(e)}")
    
    return results

async def analyze_domain_results(scan_id: str, domain: str, recon_data: Dict[str, Any], domain_index: int, total_domains: int) -> Dict[str, Any]:
    """
    Analyze reconnaissance data and calculate risk score.
    
    Args:
        scan_id: The scan ID.
        domain: The domain that was scanned.
        recon_data: Reconnaissance data.
        domain_index: Index of the current domain.
        total_domains: Total number of domains.
        
    Returns:
        Dict[str, Any]: Analysis results including risk score and AI analysis.
    """
    # Calculate base progress for this domain
    base_progress = ((domain_index + 0.5) / total_domains) * 100
    
    # Update status
    scan_statuses[scan_id]["current_step"] = f"Analyzing results for {domain}"
    scan_statuses[scan_id]["progress"] = int(base_progress)
    
    # Calculate risk score
    try:
        risk_data = calculate_risk_score(domain, recon_data)
    except Exception as e:
        print(f"Error calculating risk score: {str(e)}")
        risk_data = {
            "domain": domain,
            "risk_score": 0,
            "risk_level": "Unknown",
            "risk_details": []
        }
    
    # Update status
    scan_statuses[scan_id]["current_step"] = f"Performing AI analysis for {domain}"
    scan_statuses[scan_id]["progress"] = int(base_progress + 5)
    
    # Perform AI analysis
    try:
        ai_analysis = analyze_risks(domain, risk_data)
    except Exception as e:
        print(f"Error during AI analysis: {str(e)}")
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

async def generate_domain_reports(
    scan_id: str,
    domain: str,
    recon_data: Dict[str, Any],
    analysis_results: Dict[str, Any],
    formats: List[str],
    output_dir: str,
    domain_index: int,
    total_domains: int
) -> Dict[str, str]:
    """
    Generate reports in specified formats.
    
    Args:
        scan_id: The scan ID.
        domain: The domain that was scanned.
        recon_data: Reconnaissance data.
        analysis_results: Analysis results.
        formats: Output formats.
        output_dir: Output directory.
        domain_index: Index of the current domain.
        total_domains: Total number of domains.
        
    Returns:
        Dict[str, str]: Paths to generated reports.
    """
    # Calculate base progress for this domain
    base_progress = ((domain_index + 0.8) / total_domains) * 100
    
    # Update status
    scan_statuses[scan_id]["current_step"] = f"Generating reports for {domain}"
    scan_statuses[scan_id]["progress"] = int(base_progress)
    
    risk_data = analysis_results["risk_data"]
    ai_analysis = analysis_results["ai_analysis"]
    
    report_paths = {}
    
    # Create domain directory
    domain_dir = os.path.join(output_dir, domain.replace(".", "_"))
    os.makedirs(domain_dir, exist_ok=True)
    
    # Generate JSON report
    if "json" in formats:
        json_path = os.path.join(domain_dir, f"{domain}_report.json")
        try:
            report = generate_json_report(domain, recon_data, risk_data, ai_analysis, json_path)
            report_paths["json"] = json_path
        except Exception as e:
            print(f"Error generating JSON report: {str(e)}")
    
    # Generate Markdown report
    if "md" in formats or "markdown" in formats:
        md_path = os.path.join(domain_dir, f"{domain}_report.md")
        try:
            # First generate JSON report if not already done
            if "json" not in formats:
                report = generate_json_report(domain, recon_data, risk_data, ai_analysis)
            else:
                with open(report_paths["json"], 'r') as f:
                    report = json.load(f)
            
            markdown = generate_markdown_report(report, md_path)
            report_paths["md"] = md_path
        except Exception as e:
            print(f"Error generating Markdown report: {str(e)}")
    
    # Generate HTML report
    if "html" in formats:
        html_path = os.path.join(domain_dir, f"{domain}_report.html")
        try:
            # First generate JSON report if not already done
            if "json" not in formats:
                report = generate_json_report(domain, recon_data, risk_data, ai_analysis)
            else:
                with open(report_paths["json"], 'r') as f:
                    report = json.load(f)
            
            html = generate_html_report(report, html_path)
            report_paths["html"] = html_path
        except Exception as e:
            print(f"Error generating HTML report: {str(e)}")
    
    return report_paths

if __name__ == "__main__":
    # Run the API server
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=False)
