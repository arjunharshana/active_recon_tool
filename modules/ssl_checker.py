import ssl
import socket
from colorama import Fore

def check_ssl(target, port=443):
    print(Fore.CYAN + f"[*] Checking SSL/TLS configuration for {target}:{port}")
    context = ssl.create_default_context()
    # allow self-signed certificates for checking purposes
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        #create socket and wrap with SSL
        with socket.create_connection((target, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    print(Fore.YELLOW + "[!] No SSL certificate found.")
                    return {}
                
                ssl_info = {
                    "issued_to": "Unknown",
                    "issued_by": "Unknown",
                    "valid_until": cert.get("notAfter", "Unknown"),
                    "sans": [],
                }

                # extract issued to
                if 'subject' in cert:
                    for item in cert['subject']:
                        if item[0][0] == 'commonName':
                            ssl_info["issued_to"] = item[0][1]
                            break
                # extract issued by
                if 'issuer' in cert:
                    for item in cert['issuer']:
                        if item[0][0] == 'commonName':
                            ssl_info["issued_by"] = item[0][1]
                            break
                # extract SANs
                if 'subjectAltName' in cert:
                    ssl_info["sans"] = [value for key, value in cert['subjectAltName'] if key == 'DNS']
                
                print(Fore.GREEN + "[+] SSL/TLS configuration retrieved successfully.")
                return ssl_info
            
    except Exception as e:
        print(Fore.RED + f"[!] Error checking SSL/TLS: {e}")
        return {}