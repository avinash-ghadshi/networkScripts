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

#Setting the checkIPaddr parameter to False
conf.checkIPaddr = False

#Getting the hardware address
hw = get_if_raw_hwaddr("enp0s3")[1]

#Creating the DHCP Discover packet
dhcp_discover = Ether(dst = "ff:ff:ff:ff:ff:ff") / IP(src = "0.0.0.0", dst = "255.255.255.255") / UDP(sport = 68, dport = 67) / BOOTP(chaddr = hw) / DHCP(options = [("message-type", "discover"), "end"])

#Sending the Discover packet and accepting multiple answers for the same Discover packet
ans, unans = srp(dhcp_discover, multi = True, iface = "enp0s3", timeout = 5, verbose = 0)

#Defining a dictionary to store mac-ip pairs
mac_ip = {}
for reply in ans:
	mac_ip[reply[1][Ether].src] = reply[1][IP].src

#Printing the results
print "\nActive DHCP servers currently residing on your LAN:\n"

for mac, ip in mac_ip.iteritems():
	print "IP Address: %s, MAC Address: %s\n" % (ip, mac)



