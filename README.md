# A Mini-SIEM Log Analyzer
A lightweight Python-based Security Information and Event Management (SIEM) tool designed to parse server logs and detect potential security threats in real-time.

## 📌 Project Overview
As part of my journey into Cybersecurity, SOC operations and penetration testing, I built this tool to simulate how automated systems monitor web server traffic. It automates the "boring" task of reading thousands of log lines to highlight actionable security events.

### Key Features:
* **Automated Log Ingestion:** Parses standard Apache Combined Log formats.
* **Brute Force Detection:** Identifies IP addresses with repeated failed login attempts (HTTP 401).
* **Suspicious Activity Flagging:** Tracks IP request frequency to detect potential reconnaissance or DDoS patterns.
* **Threshold-Based Alerting:** Includes a configurable security threshold to filter out "noise" from actual threats.

## 🛠️ Technical Stack
* **Language:** Python3 (I am using version 3.13)
* **Modules:** `re` (Regular Expressions), `collections` (Data Processing)
* **Environment:** Developed using VS Code and PowerShell.

## 🚀 How It Works
The analyzer follows a standard SOC workflow:
1.  **Ingestion:** Reads raw `access.log` files line-by-line.
2.  **Parsing:** Uses Regex to extract critical data points (IP, Status Code).
3.  **Correlation:** Groups events by IP and counts occurrences of specific status codes.
4.  **Reporting:** Generates a summary dashboard highlighting "Top Talkers" and security alerts.

## Sample Output
```text
🔍 Starting Log Analysis...
========================================
🛡️  MINI-SIEM SECURITY REPORT
========================================

[+] Top IP Addresses (Frequency):
IP Address      | Request Count
-----------------------------------
192.168.1.10    | 5
10.0.0.5        | 2
172.16.0.45     | 1

[!] Security Alerts (Failed Logins >= 3):
⚠️  ALERT: Potential Brute Force from 192.168.1.10 (5 failures)

========================================
Analysis Complete.
