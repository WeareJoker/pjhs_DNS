from scapy.all import *
import re
import sqlite3
import requests

def dns_handler(packet):
   if packet.haslayer("DNS"):
      packet = packet.payload.payload.payload
   else:
      return

   for cnt in range(packet.ancount):
      if(packet.an[cnt].type != 6):
         f.write(packet.an[cnt].rrname+" "+str(packet.an[cnt].ttl)+" "+str(packet.an[cnt].type)+" "+packet.an[cnt].rdata+"\n")   
      #print(packet.an[cnt].rrname+" "+str(packet.an[cnt].ttl)+" "+str(packet.an[cnt].type)+" "+packet.an[cnt].rdata)

   for cnt in range(packet.nscount):
      if(packet.ns[cnt].type != 6):
         f.write(packet.ns[cnt].rrname+" "+str(packet.ns[cnt].ttl)+" "+str(packet.ns[cnt].type)+" "+packet.ns[cnt].rdata+"\n")
      #print(packet.ns[cnt].rrname+" "+str(packet.ns[cnt].ttl)+" "+str(packet.ns[cnt].type)+" "+packet.ns[cnt].rdata)
   for cnt in range(packet.arcount):
      if(packet.ar[cnt].type != 6):
         f.write(packet.ar[cnt].rrname+" "+str(packet.ar[cnt].ttl)+" "+str(packet.ar[cnt].type)+" "+packet.ar[cnt].rdata+"\n")
      #print(packet.ar[cnt].rrname+" "+str(packet.ar[cnt].ttl)+" "+str(packet.ar[cnt].type)+" "+packet.ar[cnt].rdata)
   #print '\n'


# live
#def live_condition():
#   sniff(iface= "eth0", prn=dns_handler, filter="udp port 53")

f=open("dns.txt","w")
f.write("name ttl type data")

sniff(iface= "eth0", prn=dns_handler, filter="udp port 53")

f.close()
# .pcap
def pcap_condition():
   pcap_file=""
   pcap=rdpcap(pcap_file)

   for packet in pcap:
      dns_handler(packet)