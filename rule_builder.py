from scapy.all import *
import base64



def start(packet_objects, attacker, target, proto):
   for i in packet_objects:
      if i['object_type'].lower() == proto.lower().strip():
         if (i['object'].source_IP == attacker or i['object'].dst_IP == attacker) and (i['object'].source_IP == target or i['object'].dst_IP == target):
            print "importing pcaket"
            packet = IP(base64.b64decode(i['object'].base64packet))
            packet.show()

if __name__ == '__main__':
   start()   
