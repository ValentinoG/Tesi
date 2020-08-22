import time
import scapy.all as scapy
starttime = time.time()
while True:
	scapy.sendp(scapy.Ether(dst='ff:ff:ff:ff:ff:ff',src='08:00:27:24:32:1f')/scapy.IP(src=str(scapy.RandIP()),dst=str(scapy.RandIP()))/scapy.TCP(sport=2321,dport=23423,flags='R',options=[('Timestamp',(0,0))]))
	time.sleep(1)
