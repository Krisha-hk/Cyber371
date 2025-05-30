from scapy.all import *
from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind

SNMP_SERVER = "192.168.56.4"  
COMMUNITY = "public"
OID = "1.3.6.1.2.1.1.1.0"     # sysDescr (System Description)

# Create the SNMP GET request packet
snmp_request = IP(dst=SNMP_SERVER)/UDP(sport=RandShort(), dport=161)/SNMP(
    community=COMMUNITY,
    PDU=SNMPget(varbindlist=[SNMPvarbind(oid=OID)])
)

print(f"Sending SNMP GET to {SNMP_SERVER} for OID {OID}...")
response = sr1(snmp_request, timeout=5, verbose=0)

if response:
    response.show()
else:
    print("No response from SNMP server.")
