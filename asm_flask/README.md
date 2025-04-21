# Attack Surface Monitoring Tool

A comprehensive tool for monitoring and analyzing the attack surface of domains, providing detailed reconnaissance, risk scoring, and AI-powered analysis.

## Features

- **Domain Input**: Scan individual domains or bulk import from CSV files
- **Comprehensive Reconnaissance**:
  - Subdomain enumeration and live detection
  - WHOIS and DNS record analysis
  - Port scanning and service fingerprinting
  - Technology stack detection
  - SSL/TLS configuration analysis
  - HTTP header security audit
  - Sensitive path discovery
  - OSINT and breach data checks
- **Risk Analysis**:
  - Detailed risk scoring based on findings
  - AI-powered analysis using free alternatives (Gemini)
  - Specific recommendations for remediation
- **Flexible Output**:
  - Structured JSON reports
  - Markdown reports
  - Interactive HTML reports with responsive design
- **Multiple Interfaces**:
  - Command-line interface (CLI)
  - Web interface with API endpoints
  - Support for both individual domains and CSV file input

## Installation

### Prerequisites

- Python 3.10 or higher
- Nmap
- Whois

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/asm-tool.git
   cd asm-tool
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install system dependencies (on Ubuntu/Debian):
   ```bash
   sudo apt-get update
   sudo apt-get install -y nmap whois
   ```

## Usage

### Command Line Interface

#### Scan a single domain:

```bash
python cli.py -d example.com -o output_dir
```

#### Scan multiple domains from a CSV file:

```bash
python cli.py -i domains.csv -o output_dir
```

#### Specify modules to run:

```bash
python cli.py -d example.com -m subdomain,port,ssl -o output_dir
```

#### Choose output formats:

```bash
python cli.py -d example.com -o output_dir -f json,md,html
```

#### Full options:

```bash
python cli.py --help
```

### Web Interface and API

#### Start the web server:

```bash
python api.py
```

Then open your browser and navigate to `http://localhost:8000`

#### API Endpoints:

- `POST /scan/domain`: Scan a single domain
- `POST /scan/csv`: Scan domains from a CSV file
- `GET /api/status/{scan_id}`: Get scan status
- `GET /reports/{scan_id}/{format}`: Get a report in the specified format
- `GET /download/{scan_id}`: Download all reports as a ZIP file

## Module Structure

```
asm_tool/
├── cli.py                  # Command line interface
├── api.py                  # Web interface and API
├── modules/
│   ├── input/              # Input handling modules
│   │   └── csv_reader.py   # CSV file reader
│   ├── reconnaissance/     # Reconnaissance modules
│   │   ├── subdomain_enum.py
│   │   ├── live_subdomain.py
│   │   ├── whois_dns.py
│   │   ├── port_scanner.py
│   │   ├── service_fingerprint.py
│   │   ├── tech_detector.py
│   │   ├── ssl_analyzer.py
│   │   ├── header_security.py
│   │   ├── path_discovery.py
│   │   └── osint_breach.py
│   ├── risk_analysis/      # Risk analysis modules
│   │   ├── risk_scorer.py  # Risk scoring
│   │   └── ai_analyzer.py  # AI analysis
│   └── output/             # Output formatting modules
│       ├── json_formatter.py
│       ├── markdown_exporter.py
│       └── html_exporter.py
├── templates/              # Web interface templates
├── static/                 # Static files for web interface
├── data/                   # Sample data and wordlists
├── output/                 # Default output directory
└── tests/                  # Test modules
```

## Detailed Module Documentation

### Input Module

The input module handles reading domains from CSV files. The CSV file should have a `domain` column.

Example CSV format:
```csv
domain
example.com
google.com
```

### Reconnaissance Modules

#### Subdomain Enumeration

Discovers subdomains using DNS enumeration techniques and public sources.

#### Live Subdomain Detection

Checks which discovered subdomains are live and responding to requests.

#### WHOIS & DNS Analysis

Retrieves WHOIS information and DNS records for the target domain.

#### Port Scanning

Scans for open ports on the target domain using Nmap.

#### Service Fingerprinting

Identifies services running on open ports and their versions.

#### Technology Stack Detection

Detects technologies, frameworks, and libraries used by the target website.

#### SSL/TLS Analysis

Analyzes SSL/TLS configuration, certificates, and vulnerabilities.

#### HTTP Header Security Audit

Checks for security-related HTTP headers and identifies missing ones.

#### Sensitive Path Discovery

Discovers potentially sensitive paths and directories on the target website.

#### OSINT & Breach Check

Checks if the domain or associated emails have been involved in data breaches.

### Risk Analysis Modules

#### Risk Scoring

Calculates a risk score based on the findings from the reconnaissance modules. The score ranges from 0 to 100, with higher scores indicating higher risk.

Risk levels:
- **Critical** (85-100): Immediate attention required
- **High** (70-84): Significant risk
- **Medium** (50-69): Moderate risk
- **Low** (25-49): Low risk
- **Informational** (0-24): Minimal risk

#### AI Analysis

Uses free AI alternatives (Gemini) to analyze the findings and provide recommendations. If the AI API is unavailable, falls back to rule-based analysis.

### Output Modules

#### JSON Formatter

Generates structured JSON reports containing all findings, risk scores, and recommendations.

#### Markdown Exporter

Converts JSON reports to human-readable Markdown format.

#### HTML Exporter

Creates interactive HTML reports with responsive design and visual indicators for risk levels.

## Examples

### Example 1: Basic Scan

```bash
python cli.py -d example.com -o output_dir
```

This will run all reconnaissance modules on `example.com` and save the results to `output_dir`.

### Example 2: Targeted Scan

```bash
python cli.py -d example.com -m subdomain,ssl,header -o output_dir -f html
```

This will run only the subdomain enumeration, SSL/TLS analysis, and HTTP header security audit modules on `example.com` and save the results as an HTML report.

### Example 3: Bulk Scan

```bash
python cli.py -i domains.csv -o output_dir -f json,md,html
```

This will scan all domains in `domains.csv` and save the results in JSON, Markdown, and HTML formats.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- This tool uses various open-source libraries and tools
- Special thanks to the cybersecurity community for inspiration and resources
