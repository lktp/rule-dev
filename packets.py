'''
TODO:
   Build out the following TCP classes:
      SSH
      TELNET


'''


#TCP Classes
class TCP(object):
   def __init__(self, source_IP, dst_IP, source_port, dest_port):
      self.source_IP = source_IP
      self.dst_IP = dst_IP
      self.source_port = source_port
      self.dest_port = dest_port

class HTTP(TCP):
   def __init__(self,source_IP, dst_IP, source_port, dest_port, payload, raw_packet):
      TCP.__init__(self,source_IP, dst_IP, source_port, dest_port)
      self.payload = payload
      self.raw_packet = raw_packet

class HTTPS(TCP):
   def __init__(self,source_IP, dst_IP, source_port, dest_port, payload, raw_packet):
      TCP.__init__(self,source_IP, dst_IP, source_port, dest_port)
      self.payload = payload
      self.raw_packet = raw_packet

class FTP(TCP):
   def __init__(self, source_IP, dst_IP, source_port, dest_port, payload, raw_packet):
      TCP.__init__(self, source_IP, dst_IP, source_port, dest_port)
      self.payload = payload
      self.raw_packet = raw_packet

#UDP classes
class UDP(object):
   def __init__(self,source_IP, dst_IP, source_port, dest_port, payload, raw_packet):
      self.source_IP = source_IP
      self.dst_IP = dst_IP
      self.source_port = source_port
      self.dest_port = dest_port

class DNS(UDP):
   def __init__(self,source_IP, dst_IP, source_port, dest_port, payload, raw_packet):
      UDP.__init__(self,source_IP, dst_IP, source_port, dest_port)
      self.payload = payload
      self.raw_packet = raw_packet


#ICMP class
class ICMP(object):
   def __init__(self, source_IP, dst_IP):
      self.source_IP = source_IP
      self.dst_IP = dst_IP



