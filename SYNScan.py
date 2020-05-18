#!/usr/bin/env python

#Importing the logging module
import logging

#This will suppress all messages that have a lower level of seriousness than error messages.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

#Importing Scapy and handling the ImportError exception
try:
    from scapy.all import *

except ImportError:
    print "Scapy package for Python is not installed on your system."
    print "Get it from https://pypi.python.org/pypi/scapy and try again."
    sys.exit()

#Defining the destination name/IP
#target = '172.16.1.2'
target = '172.16.1.3'

#Performing the scan - multiple ports
ans, unans = sr(IP(dst = target) / TCP(sport = RandShort(), dport = [111, 135, 22], flags = "S"), timeout = 5)

#The results, based on open/closed ports
for sent, received in ans:
	if received.haslayer(TCP) and str(received[TCP].flags) == "18":
                print str(sent[TCP].dport) + " is OPEN!"
	elif received.haslayer(TCP) and str(received[TCP].flags) == "20":
		print str(sent[TCP].dport) + " is closed!"
	elif received.haslayer(ICMP) and str(received[ICMP].type) == "3":
		print str(sent[TCP].dport) + " is filtered!"

#Handling unanswered packets
for sent in unans:
        print str(sent[TCP].dport) + " is filtered!"

'''
An attacker uses a SYN scan to determine the status of ports on the remote target. 

RFC 793 defines the required behavior of any TCP/IP device in that an incoming connection request begins with a SYN packet, which in turn must be followed by a SYN/ACK packet from the receiving service.

When a SYN is sent to an open port and unfiltered port, a SYN/ACK will be generated.

When a SYN packet is sent to a closed port a RST is generated, indicating the port is closed. When SYN scanning to a particular port generates no response, or when the request triggers ICMP Type 3 unreachable errors, the port is filtered.

Source: https://capec.mitre.org/data/definitions/287.html
'''
