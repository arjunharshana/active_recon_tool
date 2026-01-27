import socket
from colorama import Fore

def grab_service_banner(target, port):
    # attempt to connect to a port and grab the service banner
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        
        # for http ports, we have to send a msg to force a response
        if port in [80, 8080, 443]:
            msg = f"HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n"
            sock.send(msg.encode())
        
        banner = sock.recv(1024).decode().strip()

        sock.close()
        if banner:
            return banner
        else:
            return None
    except socket.timeout:
        print(Fore.YELLOW + f"[-] Connection to port {port} timed out")
        return None
    except Exception as e:
        print(Fore.RED + f"[-] Error grabbing banner from port {port}: {e}")
        return None