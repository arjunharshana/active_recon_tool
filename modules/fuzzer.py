import requests
import sys
from colorama import Fore
from tqdm import tqdm

def fuzz_directories(base_url, wordlist_path):
    # we will brute force directories using the provided wordlist
    found_paths = []
    try:
        with open(wordlist_path, 'r') as f:
            words = [line.strip() for line in  f if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + "[!] Wordlist file not found: {}".format(wordlist_path))
        return []
    
    session = requests.Session()
    
    try:
        for word in tqdm(words, unit="req", ncols=70, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
            url = f"{base_url}/{word}"
            try:
                response = session.get(url, timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    print(Fore.GREEN + "[+] Found: {}".format(url))
                    found_paths.append((url, 200))
                elif response.status_code == 403:
                    print(Fore.YELLOW + "[*] Forbidden: {}".format(url))
                    found_paths.append((url, 403))
                elif response.status_code in [301, 302]:
                    print(Fore.BLUE + "[*] Redirected: {} (Status: {})".format(url, response.status_code))
                    found_paths.append((url, response.status_code))
            except requests.RequestException:
                continue
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Fuzzing interrupted by user.")
        return found_paths
    
    return found_paths