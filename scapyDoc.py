#!/usr/bin/python

import sys
import socket

try:
    from scapy.all import *
except:
    hostname = socket.gethostname()
    print("scapy not installed on "+str(hostname)+" ("+str(socket.gethostbyname(hostname))+")")

def validateCommand(cmd):
    if cmd in dir(scapy.all):
        return True
    return False

def printDoc(cmd):
    if not validateCommand(cmd):
        print(str(cmd)+": Not Found")
        sys.exit()

    x = eval(cmd).__doc__
    print(str(x))

if __name__ == '__main__':
    if len(sys.argv) == 2:
        sys.exit(printDoc(sys.argv[1]))

    print("Invalid Argument")
    print("Usage: python "+str(sys.argv[0])+" <scapy command>")
    print("E.g.: python "+str(sys.argv[0])+" sniff")
    sys.exit()
