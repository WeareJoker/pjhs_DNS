from scapy.all import *
import re
import sys
import os

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

'''
# read pcap file
def pcap_condition():
   filename=raw_input("Input Filename : ")
   pcap=rdpcap(filename)

   for packet in pcap:
      dns_handler(packet)

# live condition
def live_condition():
   sniff(iface= "tap0", prn=dns_handler, filter="udp port 53")
'''

if __name__ == '__main__':
   if(len(sys.argv) != 2):
      if(sys.argv[1] not in ["live", "pcap"]):
         print "Input Condition 'live' or 'pcap'"
         sys.exit()
   else:
      f=open("dns.txt","w")
      f.write("name ttl type data")
      if(sys.argv[1]=="live"):
         sniff(iface="tap0", prn=dns_handler, filter="udp port 53")
      elif(sys.argv[1]=="pcap"):
         filename = raw_input("Input File Name : ")
         now_path = os.path.dirname(os.path.abspath(__file__))
         pcap_path = os.path.join(now_path, filename)
         pcap = rdpcap(pcap_path)
         for packet in pcap:
            dns_handler(packet)

   f.close()