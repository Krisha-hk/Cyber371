import scapy.all as scapy
import time

def measure_amplification(reflector_ip, service="DNS", port=None):
    iface = scapy.conf.iface
    port = port or {"DNS": 53, "NTP": 123, "SNMP": 161}.get(service, None)
    filter_exp = f"udp and src host {reflector_ip} and dst port >= 1024"

    print(f"Listening on {iface} for {service} response...")
    scapy.sniff(timeout=3, filter=filter_exp, iface=iface, store=0)

    if service == "DNS":
        request = scapy.IP(dst=reflector_ip)/scapy.UDP(sport=RandShort(), dport=port)/scapy.DNS(rd=1, qd=scapy.DNSQR(qname="example.com", qtype="ANY"))
    elif service == "NTP":
        request = scapy.IP(dst=reflector_ip)/scapy.UDP(sport=RandShort(), dport=port)/scapy.Raw(load=b'\x17\x00\x03\x2a' + b'\x00' * 4)
    elif service == "SNMP":
        request = scapy.IP(dst=reflector_ip)/scapy.UDP(sport=RandShort(), dport=port)/scapy.Raw(load=b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x70\xb5\x50\x4b\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00')
    else:
        raise ValueError("Unsupported service")

    req_len = len(bytes(request))
    ans = scapy.sr1(request, timeout=2, verbose=0)
    if ans:
        res_len = len(bytes(ans))
        ratio = res_len / req_len
        print(f"\nService: {service}\nRequest size: {req_len} bytes\nResponse size: {res_len} bytes\nAmplification ratio: {ratio:.2f}")
        ans.show()
    else:
        print(f"No response received from {service}")
