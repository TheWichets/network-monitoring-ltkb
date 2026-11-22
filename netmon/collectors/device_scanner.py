import ipaddress
import psutil
import socket
from scapy.all import ARP, Ether, srp, conf

conf.verb = 0

def get_local_subnet():
    ...
    
def arp_scan():
    ...
    
def mesure_latency():
    ...
    
def resolve_hostname():
    ...
    
def scan_device():
    ...
    
if __name__ == "__main__":
    for d in scan_device():
        print(d)