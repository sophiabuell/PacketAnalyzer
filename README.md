# PacketAnalyzer

usage: alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]

A network sniffer that identifies basic vulnerabilities

optional arguments:
  -h, --help    show this help message and exit
  -i INTERFACE  Network interface to sniff on
  -r PCAPFILE   A PCAP file to read

##Correctly Implemented: 
To the best of my knowledge all elements of the project are completed correctly. 
I had some trouble with the protocols and making the analizer work correctly for all of 
them. VLAN was one I was unable to get to work correctly because it has no IP layer.

##Collaboration: 
I talked with Viet about the assignment without discussing specifics or sharing any code.
I also asked general questions of my community and friends in the cyber security world 
 on VetSec and OperationCode CyberSec slack channels for clarification on how attacks/scans 
 worked and some lingering questions I had after the lectures. My brother also had fun 
 answering some of my lingering questions on how these scans are implemented. 

## Hours: 
I spent approx 8 hours total on the assignment including reading and research. Though I spent a 
bit of extra time coming back up to speed with python combining packets to reasonable clusters
to reduce number of alerts. I removed that portion of the code as its not effective for a real
time analyzer. 

##Dependencies
I used python 3, 
scapy, argparse. 

## 

## What I would do differently: 
I would group the packets by scan reasonably to not overload the user with thousands of alerts if 
they are analyzing a static pcap. With regard to detecting them I would want to work on expanding 
the protocols my sniffer detects. 