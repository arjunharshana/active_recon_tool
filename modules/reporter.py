import os
from datetime import datetime
from colorama import Fore

def save_active_report(target, open_ports, service_data, fuzz_results, dns_results, ssl_results, waf_results):
    # Create reports directory if needed
    if not os.path.exists("reports"):
        os.makedirs("reports")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"reports/Active_{target}_{timestamp}.txt"

    print(Fore.CYAN + f"\n[*] Saving detailed report to: {filename}")

    try:
        with open(filename, "w", encoding="utf-8") as f:
            # header
            f.write(f"==================================================\n")
            f.write(f"   ACTIVE RECON REPORT: {target}\n")
            f.write(f"   Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"==================================================\n\n")

            # DNS Results
            f.write("[*] DNS ENUMERATION\n")
            f.write("-" * 40 + "\n")
            
            if dns_results:
                # Standard Records
                if "records" in dns_results and dns_results["records"]:
                    f.write("[+] Standard Records:\n")
                    for r_type, values in dns_results["records"].items():
                        for val in values:
                            f.write(f"    - {r_type}: {val}\n")
                    f.write("\n")
                
                # Zone Transfer
                if dns_results.get("zone_transfer"):
                    f.write("[!] CRITICAL: Zone Transfer (AXFR) was SUCCESSFUL!\n")
                    f.write("    (Check terminal output for full dump)\n\n")
                
                # Subdomains found
                if "subdomains" in dns_results and dns_results["subdomains"]:
                    f.write(f"[+] Subdomains Found: {len(dns_results['subdomains'])}\n")
                    for sub, ip in dns_results["subdomains"]:
                        f.write(f"    - {sub:<30} -> {ip}\n")
                else:
                    f.write("    No subdomains found via brute-force.\n")
            else:
                f.write("    DNS Enumeration was skipped or returned no data.\n")
            f.write("\n")

            # waf Results
            f.write("[*] WAF/IPS DETECTION\n")
            f.write("-" * 40 + "\n")
            if waf_results:
                f.write(f"[+] Detected WAF/IPS: {', '.join(waf_results)}\n")
            else:
                f.write("    No WAF/IPS detected.\n")
            f.write("\n")

            # Port Scan Results
            f.write("[*] OPEN PORTS & SERVICES\n")
            f.write("-" * 40 + "\n")
            f.write(f"{'PORT':<10} {'STATUS':<10} {'SERVICE BANNER'}\n")
            f.write("-" * 40 + "\n")
            
            if open_ports:
                for port in open_ports:
                    # Get the banner we found, or "Unknown"
                    banner = service_data.get(port, "Unknown")
                    f.write(f"{port:<10} {'OPEN':<10} {banner}\n")
            else:
                f.write("No open ports found.\n")
            f.write("\n")

            # SSL/TLS Results
            if ssl_results:
                f.write("[*] SSL/TLS CERTIFICATE INFO\n")
                f.write("-" * 40 + "\n")
                f.write(f"    Issued To:   {ssl_results.get('issued_to')}\n")
                f.write(f"    Issued By:   {ssl_results.get('issued_by')}\n")
                f.write(f"    Valid Until: {ssl_results.get('valid_until')}\n\n")
                
                if ssl_results.get("sans"):
                    f.write(f"    [+] Subject Alternative Names ({len(ssl_results['sans'])}):\n")
                    for san in ssl_results['sans']:
                        f.write(f"        - {san}\n")
                f.write("-" * 40 + "\n\n")

            
            # Directory Fuzzing Results
            f.write("[*] DIRECTORY FUZZING RESULTS\n")
            f.write("-" * 40 + "\n")
            
            if fuzz_results:
                for url, status in fuzz_results:
                    f.write(f"[{status}] {url}\n")
            else:
                f.write("No hidden directories found (or fuzzing was disabled).\n")
            f.write("\n")
            
            f.write("-" * 40 + "\n")
            f.write("Scan completed successfully.\n")

        print(Fore.GREEN + f"[+] Report saved successfully!")

    except Exception as e:
        print(Fore.RED + f"[!] Failed to save report: {e}")