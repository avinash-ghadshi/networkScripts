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

def arp_monitor(packet):
	if ARP in packet and packet[ARP].op == 1: #ARP Request (who-has ...?)
	        return "ARP Request: Device " + packet[ARP].psrc + " asking about: " + packet[ARP].pdst
	elif ARP in packet and packet[ARP].op == 2: #ARP Reply (is-at ...)
		return "ARP Response: Device " + packet[ARP].hwsrc + " has this address: " + packet[ARP].psrc

#Performing the monitoring
sniff(prn = arp_monitor, filter = "arp", count = 20, store = 0)
