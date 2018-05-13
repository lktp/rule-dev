'''
TO DO

work on the TCP parser

ADD the UDP sizza in


'''


from scapy.all import *
from packets import *

def parse_tcp(packet):
   packet_object = ''
   object_type = ''
   '''
   source_IP, dst_IP, source_port, dest_port, payload, raw_packet
   '''
   source_IP = packet.getlayer('IP').src
   dst_IP = packet.getlayer('IP').dst
   source_port = packet.getlayer('TCP').sport
   dest_port = packet.getlayer('TCP').dport
   if packet.haslayer(Raw):
      payload = packet.load
   else:
      payload = ''  
   raw_packet = raw(packet).encode('HEX')
   if source_port == 80 or dest_port == 80:
      packet_object = HTTP(source_IP, dst_IP, source_port, dest_port, payload, raw_packet)
      object_type = 'HTTP'
   elif source_port == 443 or dest_port == 443:
      packet_object = HTTPS(source_IP, dst_IP, source_port, dest_port, payload, raw_packet)
      object_type = 'HTTPS'
   elif source_port == 22 or dest_port == 22:
      packet_object = SSH(source_IP, dst_IP, source_port, dest_port, payload, raw_packet)   
      object_type = 'SSH'
   elif source_port == 23 or dest_port == 23:
      packet_object = TELNET(source_IP, dst_IP, source_port, dest_port, payload, raw_packet)
      object_type = 'TELNET'
   else:
      #packet_object = WEIRD(source_IP, dst_IP, source_port, dest_port, payload, raw_packet)
      #object_type = 'WEIRD'
      packet_object = ''
      object_type = '' 
      
   return packet_object, object_type

def parse_udp(packet):
   pass

def parse_icmp(packet):
   pass

def weird_packet(packet):
   pass

def start(packets):
   packet_objects = []
   count = 0

   for packet in packets:
      if packet.haslayer('TCP'):
         packet_obj, object_type = parse_tcp(packet)
         dict = {'object': packet_obj, 'object_type': object_type}
         packet_objects.append(packet_obj)
      elif packet.haslayer('UDP'):
         print 'UDP'
         parse_udp(packet)
      elif packet.haslayer('ICMP'):
         print 'ICMP'
         parse_ICMP(packet)
      else:
         print 'Weird'
         weird_packet(packet)
      count +=1

if __name__ == '__main__':

   test_data = 'testdata/test_pcap.pcap'
   packets = rdpcap(test_data)
   start(packets)
