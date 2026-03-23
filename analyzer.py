import re
from collections import Counter

# --- CONFIGURATION ---
LOG_FILE = "D:\Coding\Python_Projects\mini_siem\sample_logs.log"
FAILED_THRESHOLD = 3  #Sound the Alert if failed logins >= 3

def run_siem_analysis():
    # 1. Initialize our 'Buckets'
    all_ips = []
    failed_login_ips = []

    # Regex: Group 1 is the IP, Group 2 is the Status Code
    log_pattern = r'(\d+\.\d+\.\d+\.\d+).*?\s(\d{3})\s'

    print("🔍🤨 Starting Log Analysis...\n")

    try:
        # 2. INGESTION & PARSING
        with open(LOG_FILE, 'r') as file:
            for line in file:
                match = re.search(log_pattern, line)
                if match:
                    ip = match.group(1)
                    status = match.group(2)

                    # Track for general frequency
                    all_ips.append(ip)

                    # Track specifically for 401 Unauthorized (Failed Logins)
                    if status == "401":
                        failed_login_ips.append(ip)

        # 3. (Counting the occurrences)
        ip_counts = Counter(all_ips)
        failed_counts = Counter(failed_login_ips)

        # 4. THE REPORT 
        print("=" * 40)
        print("🛡️  MINI-SIEM SECURITY REPORT")
        print("=" * 40)

        # Section A: IP Frequency (Who is most active?)
        print(f"\n[+] Top IP Addresses (Frequency):")
        print(f"{'IP Address':<15} | {'Request Count'}")
        print("-" * 35)
        for ip, count in ip_counts.most_common(5): # Top 5 most active
            print(f"{ip:<15} | {count}")

        # Section B: Brute Force Detection
        print(f"\n[!] Security Alerts (Failed Logins >= {FAILED_THRESHOLD}):")
        alerts_found = False
        for ip, count in failed_counts.items():
            if count >= FAILED_THRESHOLD:
                print(f"⚠️  ALERT: Potential Brute Force from {ip} ({count} failures)")
                alerts_found = True
        
        if not alerts_found:
            print("✅ No suspicious login activity detected.")

        print("\n" + "=" * 40)
        print("Analysis Complete.")

    except FileNotFoundError:
        print(f"❌ Error: Could not find {LOG_FILE}. Make sure it is in the same folder.")

if __name__ == "__main__":
    run_siem_analysis()