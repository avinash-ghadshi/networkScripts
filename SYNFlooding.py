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

#Defining the target machine
target = '172.16.1.2'

#Defining the packet structure
packet = IP(dst = target) / TCP(sport = RandShort(), dport = 111, seq = 333, flags = "S")

#Sending the packet in a loop
srloop(packet, inter = 0.1, retry = 2, timeout = 5, count = 10000)
