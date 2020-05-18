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
ans, unans = sr(IP(dst = target)/TCP(dport = [111, 135, 22], flags = "A"), timeout = 5)

#The results, based on filtered/unfiltered ports
for sent, received in ans:
	if received.haslayer(TCP) and str(received[TCP].flags) == "4":
		print str(sent[TCP].dport) + " is UNFILTERED!"
	elif received.haslayer(ICMP) and str(received[ICMP].type) == "3":
		print str(sent[TCP].dport) + " is filtered!"

#Handling unanswered packets
for sent in unans:
        print str(sent[TCP].dport) + " is filtered!"

'''
An attacker uses TCP ACK segments to gather information about firewall or ACL configuration.

The purpose of this type of scan is to discover information about filter configurations rather than port state. 

When a TCP ACK segment is sent to a closed port, or sent out-of-sync to a listening port, the RFC 793 expected behavior is for the device to respond with a RST. Getting RSTs back in response to a ACK scan gives the attacker useful information that can be used to infer the type of firewall present. Stateful firewalls will discard out-of-sync ACK packets, leading to no response. When this occurs the port is marked as filtered. 

When RSTs are received in response, the ports are marked as unfiltered, as the ACK packets solicited the expected behavior from a port.

Source: https://capec.mitre.org/data/definitions/305.html
'''
