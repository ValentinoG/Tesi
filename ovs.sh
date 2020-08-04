#/bin/sh

ip tuntap add mode tap vport1
ip tuntap add mode tap vport2
ip tuntap add mode tap vport3
ip tuntap add mode tap vport4

ip link set mybridge up

ip link set vport1 up
ip link set vport2 up
ip link set vport3 up
ip link set vport4 up
