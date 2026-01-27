import socket
import threading
from queue import Queue
from colorama import Fore

open_ports = []

# prevent two threads from printing simultaneously
print_lock = threading.Lock()

# function to scan a single port
def scan_port(target, port):
    # attempt to connect to a port

    try:
        #create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:
            with print_lock:
                print(Fore.GREEN + "[+] Port {} is open".format(port))
            sock.close()
            return True
        sock.close()
        return False
    except Exception:
        return False

# worker function for threads
def worker(target, queue):
    while not queue.empty():
        port = queue.get()
        if scan_port(target, port):
            open_ports.append(port)
        queue.task_done()

def scan_ports(target, start_port, end_port, thread_count):

    print(Fore.CYAN + f"[*] Scanning {target} from port {start_port} to {end_port}...")
    
    global open_ports
    open_ports = []

    # create a queue to hold the ports to scan
    queue = Queue()
    for port in range(start_port, end_port + 1):
        queue.put(port)

    thread_list = []
    for _ in range(thread_count):
        thread = threading.Thread(target=worker, args=(target, queue))
        thread.daemon = True
        thread.start()
        thread_list.append(thread)
        
    queue.join()

    print(Fore.CYAN + "[*] Port scanning completed.")
    return sorted(open_ports)