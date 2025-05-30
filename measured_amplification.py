from scapy.all import IP, UDP, DNS, DNSQR, Raw, sr1, RandShort

def measure_amplification(reflector_ip, service="DNS", port=None):
    port = port or {"DNS": 53, "NTP": 123, "SNMP": 161}.get(service)
    if port is None:
        raise ValueError("Unsupported service")

    if service == "DNS":
        request = IP(dst=reflector_ip)/UDP(sport=RandShort(), dport=port)/DNS(rd=1, qd=DNSQR(qname="example.com", qtype="ANY"))
    elif service == "NTP":
        request = IP(dst=reflector_ip)/UDP(sport=RandShort(), dport=port)/Raw(load=b'\x17\x00\x03\x2a' + b'\x00' * 4)
    elif service == "SNMP":
        request = IP(dst=reflector_ip)/UDP(sport=RandShort(), dport=port)/Raw(load=b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x70\xb5\x50\x4b\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00')

    req_len = len(bytes(request))
    print(f"[+] Sending {service} packet ({req_len} bytes) to {reflector_ip}")
    
    ans = sr1(request, timeout=2, verbose=0)
    if ans:
        res_len = len(bytes(ans))
        ratio = res_len / req_len
        print(f"[+] Received response of {res_len} bytes")
        print(f"[=] Amplification Ratio: {ratio:.2f}")
        ans.show()
    else:
        print(f"[-] No response received from {service}")

if __name__ == "__main__":
    measure_amplification("192.168.56.2", service="DNS")  

