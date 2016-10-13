from scapy.all import *
import re
import sqlite3
import requests

def dns_handler(packet):
   global DOMAIN_IP
   global REVERSE_DOMAIN_IP
   ip_list=[]
   re_ip=re.compile("[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}")

   if packet.haslayer("DNS"):
      packet = packet.payload.payload.payload
      
   else:
      return

   for cnt in range(packet.ancount):
      DOMAIN_IP[packet.an[cnt].rdata] = packet.an[cnt].rrname
      if len(re_ip.findall(packet.an[cnt].rdata)):
         ip_list.append(packet.an[cnt].rdata)

   for cnt in range(packet.nscount):
      DOMAIN_IP[packet.ns[cnt].rdata] = packet.ns[cnt].rrname
      if len(re_ip.findall(packet.ns[cnt].rdata)):
         ip_list.append(packet.ns[cnt].rdata)
   
   for cnt in range(packet.arcount):
      DOMAIN_IP[packet.ar[cnt].rdata] = packet.ar[cnt].rrname
      if len(re_ip.findall(packet.ar[cnt].rdata)):
         ip_list.append(packet.ar[cnt].rdata)

   print '\n'

   for i in ip_list:
      name=DOMAIN_IP[i]
      track=[]
      track.append(name)

      while(1):
         if(name in DOMAIN_IP):
            track.append(DOMAIN_IP[name])
            name=DOMAIN_IP[name]
         else:
            break

      track.reverse()
      track.append(i)	
      print track

sniff(iface= "eth0", prn=dns_handler, filter="udp port 53")
