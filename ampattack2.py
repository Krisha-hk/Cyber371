import scapy.all as scapy
import random
import time

def measure_amplification(reflector, service="DNS", port=None):
    src_ip = scapy.get_if_addr(scapy.conf.iface)
    port = port or {"DNS": 53, "NTP": 123, "SNMP": 161}.get(service, None)
    if not port:
        raise ValueError(f"No default port defined for {service}")

    if service == "DNS":
        pkt = scapy.IP(src=src_ip, dst=reflector)/scapy.UDP(sport=random.randint(1024,65535), dport=port)/scapy.DNS(rd=1, qd=scapy.DNSQR(qname="example.com", qtype="ANY"))
    elif service == "NTP":
        pkt = scapy.IP(src=src_ip, dst=reflector)/scapy.UDP(sport=random.randint(1024,65535), dport=port)/scapy.Raw(load=b'\x17\x00\x03\x2a' + b'\x00' * 4)
    elif service == "SNMP":
        pkt = scapy.IP(src=src_ip, dst=reflector)/scapy.UDP(sport=random.randint(1024,65535), dport=port)/scapy.Raw(load=b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x70\xb5\x50\x4b\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00')
    else:
        raise ValueError(f"Unsupported service: {service}")

    # Send the packet
    request_size = len(bytes(pkt))
    print(f"Sent {service} request of size {request_size} bytes to {reflector}")

    # Sniff for the response packet (timeout 3 seconds)
    def filter_pkt(p):
        return scapy.IP in p and p[scapy.IP].src == reflector and p[scapy.IP].dst == src_ip and scapy.UDP in p and p[scapy.UDP].sport == port

    responses = scapy.sniff(filter=f"udp and src host {reflector} and dst host {src_ip} and src port {port}", timeout=3, count=1)
    if responses:
        response_pkt = responses[0]
        response_size = len(bytes(response_pkt))
        amplification_ratio = response_size / request_size
        print(f"Received response size: {response_size} bytes")
        print(f"Amplification ratio: {amplification_ratio:.2f}")
        response_pkt.show()
    else:
        print("No response received.")

# Example usage
if __name__ == "__main__":
    measure_amplification("192.168.56.2", service="DNS")

