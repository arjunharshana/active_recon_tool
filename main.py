import sys
import argparse
from colorama import init, Fore
from modules.port_scanner import scan_ports

init(autoreset=True)

def main():
    # setting up argument parser
    parser = argparse.ArgumentParser(description="Active Reconnaissance Tool v1.0")

    parser.add_argument("target", help="Target domain or IP")

    # other flags 
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range to scan (default: 1-1000)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use (default: 10)")
    parser.add_argument("-w", "--wordlist", default="wordlists/common.txt", help="Path to custom wordlist for fuzzing")
    parser.add_argument("--fuzz", action="store_true", help="Enable directory fuzzing")

    args = parser.parse_args()

    # Display banner
    print(Fore.RED + r"""
    =======================================================
       ACTIVE RECONNAISSANCE TOOL - v1.0
       Target: {}  |  Ports: {}  |  Threads: {}
    =======================================================
    """.format(args.target, args.ports, args.threads))

    # port scanning 
    print(Fore.YELLOW + "[*] Starting port scan on {}".format(args.target))
    start_port, end_port = parse_ports(args.ports)
    open_ports = scan_ports(args.target, start_port, end_port, args.threads)

    if not open_ports:
        print(Fore.RED + "[!] No open ports found on {}".format(args.target))
        return

    # banner grabbing
    print(Fore.YELLOW + "[*] Starting banner grabbing on {}".format(args.target))
    #TODO: call banner grabbing function

    # directory fuzzing
    if args.fuzz:
        print(Fore.YELLOW + "[*] Starting directory fuzzing on {}".format(args.target))
    
    #TODO: call directory fuzzing function

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