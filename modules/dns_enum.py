import dns.resolver
import dns.zone
import dns.query
import dns.exception
from colorama import Fore


def enumerate_dns(domain, wordlist_path):
    results = {
        "records": {},
        "subdomains": [],
        "zone_transfer": None,
    }

    # checking standard DNS records
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
    print (Fore.YELLOW + f"[*] Enumerating DNS records for {domain}")

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records = [str(rdata) for rdata in answers]
            results["records"][record_type] = records
            for rdata in answers:
                print(Fore.GREEN + f"[+] Found {record_type} record: {rdata}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            continue
        except Exception as e:
            print(Fore.RED + f"[!] Error retrieving {record_type} records: {e}")

    # zone transfer attempt
    if "NS" in results["records"]:
        print(Fore.YELLOW + f"[*] Attempting zone transfer for {domain}")
        for ns in results["records"]["NS"]:
            ns = ns.rstrip('.')
            try:
                ns_ip = dns.resolver.resolve(ns, 'A')[0].to_text()
                #connect to ns_ip and attempt zone transfer
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout =5))
                if zone:
                    results["zone_transfer"] = zone
                    print(Fore.GREEN + f"[+] Zone transfer successful from {ns}")
                    for name, node in zone.nodes.items():
                        print(Fore.MAGENTA + f"      > {name.to_text(domain)}")
                    break
            except Exception:
                continue
        if not results["zone_transfer"]:
            print(Fore.RED + "[!] Zone transfer failed for all NS records.")

    # subdomain enumeration
    print(Fore.YELLOW + f"[*] Enumerating subdomains for {domain} using wordlist: {wordlist_path}")
    try:
        with open(wordlist_path, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"[!] Wordlist file not found: {wordlist_path}")
        return results
    for sub in subdomains:
        full_domain = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(full_domain, 'A')
            for rdata in answers:
                results["subdomains"].append(full_domain)
                print(Fore.GREEN + f"[+] Found subdomain: {full_domain} -> {rdata}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            continue
        except Exception as e:
            print(Fore.RED + f"[!] Error resolving subdomain {full_domain}: {e}")

    return results