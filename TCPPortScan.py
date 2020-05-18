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

#Performing the scan
ans, unans = sr(IP(dst = target) / TCP(flags = "S", dport = (1, 1024)), timeout = 5, verbose = 0)

#The results, based on open/closed ports
#Send a TCP SYN on each port. Wait for a SYN-ACK or a RST or an ICMP error (secdev.org)
for sent, received in ans:
	if received.haslayer(TCP) and str(received[TCP].flags) == "18":
		print                
		print str(sent[TCP].dport) + " is OPEN!"
	elif received.haslayer(ICMP) and str(received[ICMP].type) == "3":
		print
		print str(sent[TCP].dport) + " is filtered!"

#Handling unanswered packets
for sent in unans:
        print str(sent[TCP].dport) + " is filtered!"

print "\nAll other ports are closed.\n"
