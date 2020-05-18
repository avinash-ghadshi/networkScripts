#!/usr/bin/env python

import sys
import socket

try:
    from scapy.all import *
except:
    hostname = socket.gethostname()
    print("Scapy not installed on "+str(scapy)+" ("+str(socket.gethostbyname(hostname))+")")
    sys.exit()

def processPacket(pkt):
    if TCP in pkt:
        print(str(pkt[IP].src)+":"+str(pkt[TCP].sport)+" => "+str(pkt[IP].dst)+":"+str(pkt[TCP].dport))



sniff(iface="wlan0", prn=processPacket, count=10, timeout=20)
