import scapy.all as scapy
import random
import time

# Load NTP protocol manually
import scapy.contrib.ntp
scapy.contrib.ntp.load_contrib("ntp")
from scapy.contrib.ntp import NTP

# SNMP is built-in (no contrib)
from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind





def amp_attack(reflector, service="DNS"):
    sport = scapy.RandShort()
    if service == "DNS":
        pkt = IP(dst=reflector)/UDP(sport=sport, dport=53)/DNS(rd=1, qd=DNSQR(qname="monolith.lcs.mit.edu", qtype="ANY"))
    elif service == "NTP":
        # Mode 3 = client request, version 4
        pkt = IP(dst=reflector)/UDP(sport=sport, dport=123)/NTP(mode=3, version=4)
    elif service == "SNMP":
        pkt = IP(dst=reflector)/UDP(sport=sport, dport=161)/SNMP(
            community="public", PDU=SNMPget(varbindlist=[SNMPvarbind(oid="1.3.6.1.2.1.1.1.0")])
        )
    else:
        raise ValueError(f"Unsupported service: {service}")

    sent_size = len(bytes(pkt))
    print(f"[{service}] Sending packet of size: {sent_size} bytes")
    
    response = scapy.sr1(pkt, timeout=5, verbose=0)
    if response:
        received_size = len(bytes(response))
        ratio = received_size / sent_size
        print(f"[{service}] Received packet size: {received_size} bytes")
        print(f"[{service}] Amplification Ratio: {ratio:.2f}")
        response.show()
        return (service, sent_size, received_size, round(ratio, 2))
    else:
        print(f"[{service}] No response received.")
        return (service, sent_size, 0, 0)

# Run tests for each service
results = []
for service in ["DNS", "NTP", "SNMP"]:
    results.append(amp_attack(reflector="192.168.56.4", service=service))  # adjust IP to your test server
    time.sleep(1)  # avoid overloading

# Print final table
print("\nService\tSent Size\tReceived Size\tAmplification Ratio")
for row in results:
    print(f"{row[0]}\t{row[1]}\t\t{row[2]}\t\t{row[3]}")
