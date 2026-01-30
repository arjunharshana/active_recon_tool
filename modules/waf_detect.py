import requests
from colorama import Fore

def detect_waf(target_url):
    print(Fore.CYAN + f"[*] Detecting WAF/IPS for {target_url}")
    waf_signatures = {
        "Cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
        "AWS WAF": ["x-amz-cf-id", "awselb", "awsalb"],
        "Akamai": ["akamai", "akamai-ghost", "x-akamai-request-id"],
        "Imperva Incapsula": ["incap_ses", "visid_incap", "x-cdn"],
        "F5 BIG-IP": ["bigip", "f5_cspm"],
        "Barracuda": ["barra_counter_session", "bnI_"],
        "Wordfence": ["wordfence_verifiedhuman"],
    }

    try:
        response = requests.get(target_url, timeout=10)
        headers = str(response.headers).lower()
        cookies = str(response.cookies).lower()

        detected_wafs = []

        for waf_name, signatures in waf_signatures.items():
            for signature in signatures:
                for header_value in headers.values() or cookies.values():
                    if signature.lower() in header_value.lower():
                        detected_wafs.append(waf_name)
                        break

        if detected_wafs:
            detected_wafs = list(set(detected_wafs))  # Remove duplicates
            print(Fore.GREEN + f"[+] Detected WAF/IPS: {', '.join(detected_wafs)}")
            return detected_wafs
        else:
            print(Fore.YELLOW + "[*] No WAF/IPS detected.")
            return []

    except requests.RequestException as e:
        print(Fore.RED + f"[!] Error during WAF detection: {e}")
        return []