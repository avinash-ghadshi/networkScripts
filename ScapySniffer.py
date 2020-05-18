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

#Setting network interface in promiscuous mode
#Wikipedia: In computer networking, promiscuous mode or "promisc mode"[1] is a mode for a wired network interface controller (NIC) or wireless network interface controller (WNIC)...
#...that causes the controller to pass all traffic it receives to the central processing unit (CPU) rather than passing only the frames that the controller is intended to receive.
#This mode is normally used for packet sniffing that takes place on a router or on a computer connected to a hub.

#Also, when using our setup (VirtualBox-to-GNS3), you should go to the Settings section for the virtual machine you are using...
#...select the adapter that connects to the GNS3 network and set Promiscuous Mode: Allow All

subprocess.call(["ifconfig", "enp0s3", "promisc"], stdout = None, stderr = None, shell = False)

#Performing the sniffing function
sniff(filter = "icmp and host 172.16.1.2", iface = "enp0s3", prn = lambda x: x.summary(), count = 30, timeout = 20)



#To see the list of optional arguments for the sniff() function:
'''
>>> print sniff.__doc__
Sniff packets
sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args) -> list of packets

  count: number of packets to capture. 0 means infinity
  store: wether to store sniffed packets or discard them
    prn: function to apply to each packet. If something is returned,
         it is displayed. Ex:
         ex: prn = lambda x: x.summary()
lfilter: python function applied to each packet to determine
         if further action may be done
         ex: lfilter = lambda x: x.haslayer(Padding)
offline: pcap file to read packets from, instead of sniffing them
timeout: stop sniffing after a given time (default: None)
L2socket: use the provided L2socket
opened_socket: provide an object ready to use .recv() on
stop_filter: python function applied to each packet to determine
             if we have to stop the capture after this packet
             ex: stop_filter = lambda x: x.haslayer(TCP)
'''
