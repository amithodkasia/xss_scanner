# XSS Scanner

## Overview
This tool is used to detect **Cross-Site Scripting (XSS) vulnerabilities** in web applications.

## Features
- Scans **GET** and **POST** requests
- Supports **custom payloads**
- Multi-threaded for faster scanning
- Can bypass some **Web Application Firewalls (WAFs)**
- Saves scan results for review

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/amithodkasia/xss_scanner.git
   cd xss_scanner
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Usage
Run the tool with a URL:
```sh
python xss_scanner.py -u "http://example.com"
```

For advanced options:
```sh
python xss_scanner.py -u "http://example.com" --post --threads 10
```

## Disclaimer
This tool is for educational and ethical hacking purposes only. Use it responsibly.
