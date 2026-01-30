import sys
import argparse
from colorama import init, Fore
from modules.port_scanner import scan_ports
from modules.service_grab import grab_service_banner
from modules.fuzzer import fuzz_directories
from modules.dns_enum import enumerate_dns
from modules.ssl_checker import check_ssl
from modules.waf_detect import detect_waf
from modules.reporter import save_active_report

init(autoreset=True)

def main():
    # setting up argument parser
    parser = argparse.ArgumentParser(description="Active Reconnaissance Tool v1.0")

    parser.add_argument("target", help="Target domain or IP")

    # other flags 
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range to scan (default: 1-1000)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use (default: 10)")
    parser.add_argument("-wf", "--wordlist-fuzz", default="wordlists/common.txt", help="Path to custom wordlist for fuzzing")
    parser.add_argument("-wd", "--wordlist-dns", default="wordlists/subdomains.txt", help="Path to custom wordlist for DNS enumeration")
    parser.add_argument("--fuzz", action="store_true", help="Enable directory fuzzing")
    parser.add_argument("--dns", action="store_true", help="Enable DNS enumeration")


    args = parser.parse_args()

    dns_results = {}
    waf_results = []
    open_ports = []
    service_results = {}
    ssl_results = {}
    fuzz_results = []

    # Display banner
    print(Fore.RED + r"""
    =======================================================
       ACTIVE RECONNAISSANCE TOOL - v1.0
       Target: {}  |  Ports: {}  |  Threads: {}
    =======================================================
    """.format(args.target, args.ports, args.threads))

    # DNS enumeration
    if args.dns:
        if any(c.isalpha() for c in args.target):
            dns_results = enumerate_dns(args.target, args.wordlist_dns)
        else:
            print(Fore.RED + "[!] DNS enumeration requires a domain name.")

        if dns_results:
            print(Fore.YELLOW + "[*] DNS Enumeration completed.")

    # WAF detection
    if args.target.startswith("http://") or args.target.startswith("https://"):
        target_url = args.target
    else:
        target_url = "http://" + args.target

    waf_results = detect_waf(target_url)

    if waf_results and not args.force:
        print(Fore.RED + "[!] WAF detected. Proceeding may lead to IP blocks or false results.")
        input(Fore.YELLOW + "[*] Press Enter to continue...")
        if input().lower() != '':
            print(Fore.RED + "[!] Exiting as per user request.")
            sys.exit(0)

        
    # port scanning 
    print(Fore.YELLOW + "[*] Starting port scan on {}".format(args.target))
    start_port, end_port = parse_ports(args.ports)
    open_ports = scan_ports(args.target, start_port, end_port, args.threads)

    if not open_ports:
        print(Fore.RED + "[!] No open ports found on {}".format(args.target))
        return

    # SSL/TLS checking for HTTPS services
    if 443 in open_ports:
        print(Fore.YELLOW + "[*] Checking SSL/TLS configuration on port 443")
        ssl_results = check_ssl(args.target, 443)
    else:
        print(Fore.YELLOW + "[*] Port 443 not open; skipping SSL/TLS check.")

    # banner grabbing
    print(Fore.YELLOW + "[*] Starting banner grabbing on {}".format(args.target))
    if not open_ports:
        print(Fore.RED + "[!] No open ports found on {}".format(args.target))
    else:
        for port in open_ports:
            banner = grab_service_banner(args.target, port)
            service_results[port] = banner
            if "Error" in banner or "Timeout" in banner:
                print(Fore.LIGHTBLACK_EX + f"    > Port {port}: {banner}")
            else:
                print(Fore.GREEN + f"    > Port {port}: {banner}")

    
    # directory fuzzing
    if args.fuzz:
        print(Fore.YELLOW + "[*] Starting directory fuzzing on {}".format(args.target))
        if 80 in open_ports or 443 in open_ports:
            fuzz_results = fuzz_directories(args.target, args.wordlist_fuzz)
        else:
            print(Fore.RED + "[!] No open ports for directory fuzzing.")

        if fuzz_results:
            print(Fore.YELLOW + "[*] Fuzzing completed. Found paths:")
            for path, status in fuzz_results:
                print(Fore.GREEN + f"    > {path} (Status: {status})")
    
    # Save report
    print(Fore.YELLOW + "[*] Saving report...")
    save_active_report(args.target, open_ports, service_results, fuzz_results if args.fuzz else [], dns_results, ssl_results, waf_results)


def parse_ports(port_range):
    try:
        if '-' in port_range:
            start, end = port_range.split('-')
            return int(start), int(end)
        return int(port_range), int(port_range)
    except ValueError:
        print(Fore.RED + "[!] Invalid port range. Use format: start-end (e.g., 1-1000)")
        sys.exit(1)


if __name__ == "__main__":
    main()