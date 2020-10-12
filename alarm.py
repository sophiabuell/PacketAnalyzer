#!/usr/bin/python3

from scapy.all import *
from scapy.layers import http
import argparse

counter = 0
user_ips = []
user_names = []

def printAlert(incident, packet, payload):
    global counter
    protocol = packet[IP].summary().split('/')[1].split(' ')[1]
    print("ALERT #{0}: {1} scan is detected from {2}:{3} ({4}) ({5})".format(counter, incident, packet[IP].src, packet[IP].dport, protocol, payload))
    counter += 1

def printUserPass(packet, username, passcode):
    global counter
    protocol = packet[IP].summary().split('/')[1].split(' ')[1]
    print("ALERT #{0}: Usernames and passwords sent in-the-clear ({1}) (username: {2}, password: {3})".format(counter, protocol, username, passcode))
    counter += 1

def tryForAuth(packet):
    global counter
    global user_ips
    global user_names
    req = packet.getlayer('HTTP Request')
    if req:
        auth = req.Authorization
        if auth:
            if auth.startswith(b'Basic '):
                uname, passw = base64_bytes(auth.split(None, 1)[1]).split(b':', 1)
                printUserPass(packet, uname.decode().strip(), passw.decode().strip())
    else:
        try:
            load = packet.load
        except:
            return
        if load.find(b'USER ') >= 0:
            uname = load.split(None, 1)[1].decode('ascii').strip()
            user_ips.append(packet[IP].src)
            user_names.append(uname)
        elif load.find(b'PASS ') >=0:
            pswd = load.split(None, 1)[1].decode('ascii').strip()
            uname = user_names[user_ips.index(packet[IP].src)]
            user_ips.remove(packet[IP].src)
            user_names.remove(uname)
            printUserPass(packet, uname, pswd)
        elif load.find(b'LOGIN ') >= 0:
            uname = load.split(None, 1)[1].decode('ascii')
            pswd = load.split(None, 1)[1].decode('ascii')
            uname = uname.split(' ')[1].strip()
            pswd = pswd.split(' ')[2].strip()
            printUserPass(packet, uname, pswd)

def checkForFin(packet, otherScanDetected):
    global counter
    protocol = packet[IP].summary().split('/')[1].split(' ')[1]
    flags = packet[protocol].flags
    if flags.F and not otherScanDetected and not flags.A:
        printAlert("FIN", packet, None)
        return True
    else:
        return False

#Check for xmas first because this could be caught in FIN because that flag is also set.
def checkForXmas(packet, protocol, otherScanDetected):
    global counter
    try:
        flags = packet[protocol].flags
    except:
        print(packet[IP].summary())
        print(protocol)
        packet.show()
    if flags.F and flags.P and flags.U and not otherScanDetected:
        printAlert("XMAS", packet, None)
        return True
    else:
        return False

def checkForNikto(packet):
    global counter
    try:
        raw = packet.load.decode().strip()
    except:
        return False
    if 'nikto' in raw or 'Nikto' in raw:
        printAlert("NIKTO", packet, raw)
        return True
    return False

def checkForNull(packet, protocol):
    flags = packet[protocol].flags
    if not flags:
        printAlert("NULL", packet, None)
        return True
    return False

def checkForSMB(packet):
    global counter
    if not scanDetected:
        port = packet.dport
        if port == 139 or port == 445:
            printAlert("SMB", packet, None)
            return True
    return False

def identifyAndPrintAlerts(packet):
    scanDetected = False
    try:
        protocol = packet[IP].summary().split('/')[1].split(' ')[1]
    except:
        return checkForNikto(packet)

    if 'TCP' in protocol:
        scanDetected = checkForXmas(packet, protocol, scanDetected) or scanDetected
        checkForFin(packet, scanDetected)
        checkForNull(packet, protocol)
        checkForSMB(packet)

    scanDetected = checkForNikto(packet)
    return scanDetected

def packetcallback(packet):
     try:
        tryForAuth(packet)
        identifyAndPrintAlerts(packet)
     except:
         print("Exception occurred when trying to read packet: ")
         packet.show()
         print("Please check. ")


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
