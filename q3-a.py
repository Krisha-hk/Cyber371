#Scaffold code for part (a)
import scapy.all as scapy
import random
import time
def amp_attack(reflector, victim=None, service="DNS", port=None):
"""
Perform an amplification attack on the given reflector service.
Parameters:
- reflector: IP of the reflector server being exploted.
- victim: IP of the victim; if None, response will come back to us.
- service: The type of service exploited (default "DNS").
- port: The port to target on the reflector (if different from default).
"""

# TODO: Implement sending the attack based on the selected service.
match service:
case "DNS":
# TODO: Construct and send a DNS amplification packet
pass
case "UDP CharGen":
# TODO: Construct and send a UDP CharGen amplification packet
pass
case "Memcached":
# TODO: Construct and send a Memcached amplification
pass
case "NTP":
# TODO: Construct and send an NTP amplification packet
pass
case "SSDP":
# TODO: Construct and send a SSDP amplification packet
pass
case "SNMP":
# TODO: Construct and send an SNMP amplification packet
pass
case "CLDAP":
# TODO: Construct and send a CLDAP amplification packet
pass
case "TFTP":
# TODO: Construct and send a TFTP amplification packet
pass
case
:
_
raise ValueError(f"Unsupported service: {service}. ")
# Example call:
# amp_attack(reflector="192.168.1.2", victim="192.168.1.3", service="NTP")