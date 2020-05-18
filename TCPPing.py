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

#Performing the ping
#In cases where ICMP echo requests are blocked, we can still use various TCP Pings such as TCP SYN Ping.
#Any response to our probes will indicate a live host. Source: secdev.org
ans, unans = sr(IP(dst = "172.16.1.1-5") / TCP(dport = 111, flags = "S"), timeout = 2, iface = "enp0s3")

#The results
ans.summary(lambda(s,r): r.sprintf("%IP.src% is UP!"))
