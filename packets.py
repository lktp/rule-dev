'''
TODO:
   Build out the following TCP classes:
      SSH
      TELNET


PACKET
  |
  |
  ---> TCP 
  |      |
  |      -->HTTP
  |      |
  |      -->HTTPS
  |      |
  |      --> FTP
  |      |
  |      --> SSH
  |      |
  |      --> TELNET
  |
  ---> UDP
  |      |
  |      --> DNS
  |
  ---> ICMP

'''
#PACKET CLASS

#Main class
class PACKET(object):
   def __init__(self, source_IP, dst_IP, base64packet):
      self.source_IP = source_IP
      self.dst_IP = dst_IP
      self.base64packet = base64packet


#TCP Classes

class TCP(PACKET):
   def __init__(self, source_IP, dst_IP, source_port, dest_port, base64packet):
      PACKET.__init__(self, source_IP, dst_IP, base64packet)
      self.source_port = source_port
      self.dest_port = dest_port

class HTTP(TCP):
   def __init__(self,source_IP, dst_IP, source_port, dest_port, payload, raw_packet, base64packet):
      TCP.__init__(self,source_IP, dst_IP, source_port, dest_port, base64packet)
      self.payload = payload
      self.raw_packet = raw_packet

class HTTPS(TCP):
   def __init__(self,source_IP, dst_IP, source_port, dest_port, payload, raw_packet, base64packet):
      TCP.__init__(self,source_IP, dst_IP, source_port, dest_port, base64packet)
      self.payload = payload
      self.raw_packet = raw_packet

class FTP(TCP):
   def __init__(self, source_IP, dst_IP, source_port, dest_port, payload, raw_packet, base64packet):
      TCP.__init__(self, source_IP, dst_IP, source_port, dest_port, base64packet)
      self.payload = payload
      self.raw_packet = raw_packet

#UDP classes
class UDP(PACKET):
   def __init__(self,source_IP, dst_IP, source_port, dest_port, payload, raw_packet, base64packet):
      PACKET.__init__(self, source_IP, dst_IP, base64packet)
      self.source_port = source_port
      self.dest_port = dest_port

class DNS(UDP):
   def __init__(self,source_IP, dst_IP, source_port, dest_port, payload, raw_packet, base64packet):
      UDP.__init__(self,source_IP, dst_IP, source_port, dest_port, base64packet)
      self.payload = payload
      self.raw_packet = raw_packet


#ICMP class
class ICMP(PACKET):
   def __init__(self, source_IP, dst_IP):
      PACKET.__INIT__(self, source_IP, dst_IP)
      self.source_IP = source_IP
      self.dst_IP = dst_IP



