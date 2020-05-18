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


#Defining the destination names/IPs and ports and the exiting interface
targets = ['172.16.1.2', '172.16.1.3', '172.16.1.150', '172.16.1.100']
ports = [50743, 111, 135, 22]
interface = "enp0s3"


#Defining the TCP scan function
def tcp_scan(target, port):
	#Creating a list for the open ports
	open_ports = []
	#Performing the scan - multiple ports
	ans, unans = sr(IP(dst = target) / TCP(sport = RandShort(), dport = port, flags = "S"), timeout = 2, iface = interface, verbose = 0)

	#The results, based on open/closed ports
	for sent, received in ans:
		if received.haslayer(TCP) and str(received[TCP].flags) == "18":
			print str(sent[TCP].dport) + " is OPEN!"
			open_ports.append(int(sent[TCP].dport))
		elif received.haslayer(TCP) and str(received[TCP].flags) == "20":
			print str(sent[TCP].dport) + " is closed!"
		elif received.haslayer(ICMP) and str(received[ICMP].type) == "3":
			print str(sent[TCP].dport) + " is filtered!"

	#Handling unanswered packets
	for sent in unans:
			print str(sent[TCP].dport) + " is filtered!"

	return open_ports
				

#Checking hosts via ICMP
def icmp_scan():				
	for target in targets:
		ping_reply = srp1(Ether() / IP(dst = target) / ICMP(), timeout = 2, iface = interface, verbose = 0)
		
		if str(type(ping_reply)) == "<type 'NoneType'>" or ping_reply.getlayer(ICMP).type == "3":
			print			
			print "\n---> Host with IP address %s is down or unreachable." % target
			print
		else:
			print "\n\n---> Host with IP address %s and MAC address %s is up." % (target, ping_reply[Ether].src)
			
			print "\nTCP Ports:\n"
			#Calling the TCP scanning function
			open_ports = tcp_scan(target, ports)

			if len(open_ports) > 0:
				pkt = sr1(IP(dst = target) / TCP(dport = open_ports[0], flags = "S"), timeout = 2, iface = interface, verbose = 0)
				ttl = str(pkt[IP].ttl)
				window = str(pkt[TCP].window)
				#print ttl, window

				#Identifying the host OS based on the TTL and Window Size values in 'pkt'
				if ttl == "128" and window == "65535":
					print "\nGuessing OS type... Windows XP.\n"
				elif ttl == "128" and window == "16384":
					print "\nGuessing OS type... Windows 2000/Server 2003.\n"
				elif ttl == "128" and window == "8192":
					print "\nGuessing OS type... Windows 7/Vista/Server 2008.\n"
				elif ttl == "64" and window == "5840":
					print "\nGuessing OS type... Linux Kernel 2.x.\n"
				elif ttl == "64" and window == "14600":
					print "\nGuessing OS type... Linux Kernel 3.x.\n"
				elif ttl == "64" and window == "65535":
					print "\nGuessing OS type... FreeBSD.\n"
				elif ttl == "64" and window == "5720":
					print "Guessing OS type... Chrome OS/Android.\n"
				elif ttl == "255" and window == "4128":
					print "Guessing OS type... Cisco IOS 12.4.\n"
				elif ttl == "64" and window == "65535":
					print "Guessing OS type... MAC OS.\n"	
			else:
				print "Cannot detect host OS --> no open ports found."
			
			
#Running the function
icmp_scan()

