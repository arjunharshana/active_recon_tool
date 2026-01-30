# Active Reconnaissance Tool

A modular, multi-threaded active reconnaissance tool. This tool automates the "Attack Chain" from port scanning to directory fuzzing, WAF detection, and DNS enumeration.

> **LEGAL DISCLAIMER**: This tool is for educational purposes and authorized security testing only. Scanning targets without prior mutual consent is illegal. The developer is not responsible for any misuse or damage caused by this program.

## Features

This tool actively interacts with the target to uncover potential entry points.

- **Multi-Threaded Port Scanner**: Scans thousands of ports in seconds.
- **WAF Detection**: Identifies Firewalls (Cloudflare, AWS, Akamai) before scanning to prevent IP bans.
- **Service Enumeration**: "Banner Grabbing" to identify running software versions (SSH, FTP, HTTP).
- **Directory Fuzzer**: Brute-forces hidden paths (`/admin`, `/.env`) using custom wordlists.
- **DNS Enumeration**: Brute-forces subdomains and attempts Zone Transfers (AXFR).
- **SSL/TLS Analysis**: Extracts certificate details and Subject Alternative Names (SANs) to find hidden domains.
- **Auto-Reporting**: Generates a detailed, timestamped text report for every scan in the `reports/` folder.

---

## Installation

### Prerequisites
- Python 3.x
- Git

### Quick Start
1. **Clone the repository:**
   ```bash
   git clone https://github.com/arjunharshana/active_recon_tool.git
   cd active_recon_tool
   ```
2. **Set up Virtual Environment**
   ```bash
   python -m venv venv
   source venv/Scripts/activate  # On Windows (Git Bash)
   source venv/bin/activate    # On Linux/Mac
   ```
3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```
## Usage
  Run the tool using main.py. The only required argument is the target.

### 1. Check for WAFs :

  Check for WAFs and grab SSL certs without aggressive scanning.
```bash
  python main.py google.com -p 443-443
```
If any WAF is detected, it will ask for user input to continue. Continue at your own risk as your IP may get banned.

### 2. Standard Port Scan

Scan a port range (default is 1-1000) and define number of threads you want to use (default is 10)
```bash
python main.py [target] -p [port range] -t [threads]
```
Example:
```bash
python main.py scanme.nmap.org -p 1-1000 -t 50
```

### 3. Full Attack

Performs DNS Enum, Port Scan, Service Grab, and Directory Fuzzing.
```bash
python main.py [target] --dns --fuzz -t [threads]
```

### 4. Custom Wordlists

Specify your own lists for deeper scanning.
```bash
python main.py [target] --dns --fuzz -wd [wordlist-path-for-dns-scan] -wf [wordlist-path-for-fuzzing]
```
