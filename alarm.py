#!/usr/bin/python3

from scapy.all import *
from scapy.layers import http
import argparse

fin = 0
user_pass = []

def tryForAuth(packet, protocol):
    req = packet.getlayer(protocol)
    if req:
        req = packet.getlayer('HTTP Request')
        if req:
            auth = req.Authorization
            print("Found Auth*************************")
            if auth and auth.startswith(b'Basic '):
                uname, passw = base64_bytes(auth.split(None, 1)[1]).split(b':', 1)
                print("Username: %r, password: %r" % (uname.decode(), passw.decode()))

def checkForFin(packet):
    if packet[TCP].flags.F:
        print("Fin detected")
        fin += 1

def packetcallback(packet):
    # The following is an example of Scapy detecting HTTP traffic
    # Please remove this case in your actual lab implementation so it doesn't pollute the alerts
#    if packet[TCP].flags.F:
#        if not fin:
#            print("FIN scan identified")
    try:
        if TCP in packet:
            tryForAuth(packet, 'TCP')
        elif DNS in packet:
            tryForAuth(packet, 'DNS')
        elif ARP in packet:
            tryForAuth(packet, 'ARP')
        elif HTTP in packet:
            tryForAuth(packet, 'HTTP')
        else:
            print("Packet Not Found")

        # try:
        #    if Authorization in packet:
        #        print("Found password")
        # except:
        #     print("failed")
#        if packet[TCP].dport == 80:
            #print("HTTP (web) traffic detected! ")
    except:
        ls(packet)
        print("failed outer")

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()

if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
