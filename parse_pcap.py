'''
TO DO

work on the TCP parser

ADD the UDP sizza in


'''


from scapy.all import *
from packets import *
import rule_builder
import base64

def parse_tcp(packet):
   packet_object = ''
   object_type = ''

   source_IP = packet.getlayer('IP').src
   dst_IP = packet.getlayer('IP').dst
   source_port = packet.getlayer('TCP').sport
   dest_port = packet.getlayer('TCP').dport
   if packet.haslayer(Raw):
      payload = packet.load
   else:
      payload = ''  
   raw_packet = raw(packet).encode('HEX')
   packet_base64 = base64.b64encode(str(packet))
   if source_port == 80 or dest_port == 80:
      packet_object = HTTP(source_IP, dst_IP, source_port, dest_port, payload, raw_packet, packet_base64)
      object_type = 'HTTP'
   elif source_port == 443 or dest_port == 443:
      packet_object = HTTPS(source_IP, dst_IP, source_port, dest_port, payload, raw_packet, packet_base64)
      object_type = 'HTTPS'
   elif source_port == 22 or dest_port == 22:
      packet_object = SSH(source_IP, dst_IP, source_port, dest_port, payload, raw_packet, packet_base64)   
      object_type = 'SSH'
   elif source_port == 23 or dest_port == 23:
      packet_object = TELNET(source_IP, dst_IP, source_port, dest_port, payload, raw_packet, packet_base64)
      object_type = 'TELNET'
   else:
      #packet_object = WEIRD(source_IP, dst_IP, source_port, dest_port, payload, raw_packet, packet_base64)
      #object_type = 'WEIRD'
      packet_object = ''
      object_type = '' 
      
   return packet_object, object_type

def parse_udp(packet):
   '''
   Will be built once i figure out the logic for building rules using the TCP rules.
   '''
   pass

def parse_icmp(packet):
   '''
   Will be built once i figure out the logic for building rules using the TCP rules.
   '''   
   pass

def weird_packet(packet):
   '''
   Will be built once i figure out the logic for building rules using the TCP rules.
   '''   
   pass

def start(packets):
   packet_objects = []

   for packet in packets:
      if packet.haslayer('TCP'):
         packet_obj, object_type = parse_tcp(packet)
         obj_dict = {'object': packet_obj, 'object_type': object_type}
         packet_objects.append(obj_dict)
      elif packet.haslayer('UDP'):
         parse_udp(packet)
      elif packet.haslayer('ICMP'):
         parse_ICMP(packet)
      else:
         weird_packet(packet)
   attacker = raw_input("Type the IP of the attacker\n>>")
   target = raw_input("type the IP of the target\n>>")
   proto = raw_input("type the protocol used\n>>")
   rule_builder.start(packet_objects, attacker, target, proto)
             
if __name__ == '__main__':

   test_data = 'testdata/test_pcap.pcap'
   packets = rdpcap(test_data)
   start(packets)
