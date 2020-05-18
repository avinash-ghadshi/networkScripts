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
target = '4.2.2.1'

#Performing the traceroute
ans,unans = sr(IP(dst = target, ttl = (1, 3)) / TCP(dport = 53, flags = "S"), timeout = 5)

#The results
ans.summary(lambda(s, r) : r.sprintf("%IP.src% --> ICMP:%ICMP.type% --> TCP:%TCP.flags%"))

