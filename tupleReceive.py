#!/usr/bin/env python
import sys
import struct
import os
import socket

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
from tupleHeader import Tuple

from pyspark.sql import SparkSession
from pyspark.sql.functions import explode
from pyspark.sql.functions import split

DPORT = 0x0da2


# def handle_pkt(pkt):
#     if UDP in pkt and pkt[UDP].dport == 3490:
#         print
#         print (pkt[Tuple].age, pkt[Tuple].height, pkt[Tuple].weight)
#     #    hexdump(pkt)
#         sys.stdout.flush()


# def main():
#     ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
#     iface = ifaces[0]
#     print "sniffing on %s" % iface
#     sys.stdout.flush()
#     sniff(iface = iface,
#           prn = lambda x: handle_pkt(x))

# if __name__ == '__main__':
#     main()
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', DPORT))
    while True:
        tupl, clientAddress = s.recvfrom(100)
        tupl = struct.unpack('iii',tupl)
        print str(tupl)
        
if __name__ == '__main__':
    main()


# # Bind the socket to port 5999
# port = 3490
# serverSocket = socket(AF_INET, SOCK_DGRAM)
# serverSocket.bind(('', port))

# # Listen for clients and handle them sequentially 
# # (as opposed to async multithreaded). If the special proxy
# # server option is read from a client, then send back the
# # number of clients being handled by the proxy server. This
# # is based on the number of threads the proxy server process
# # currently owns 
# while True:
#     message, clientAddress = serverSocket.recvfrom(100)
#     if message.decode() == 'y':
#         proxyClients = os.popen('pid=$(pgrep proxy_server); cat /proc/$pid/status | grep Threads').read()
#         proxyClients = ''.join(re.findall(r'\d+', proxyClients))
#         proxyClients = str(int(proxyClients) - 1)
#         serverSocket.sendto(proxyClients.encode(), clientAddress) 
#         sys.exit()
#     message = message.decode().upper()
#     serverSocket.sendto(message.encode(), clientAddress) 



# sudo echo "JAVA_HOME=/usr" >> /etc/environment
# source /etc/environment

# def main():
#     spark = SparkSession \
#         .builder \
#         .appName("TupleFiltering") \
#         .getOrCreate()
#     socketDF = spark \
#         .readStream \
#         .format("socket") \
#         .option("host", "10.0.1.1") \
#         .option("port", 3490) \
#         .load()
#     socketDF.isStreaming()    # Returns True for DataFrames that have streaming sources
#     socketDF.printSchema()

# if __name__ == '__main__':
#     main()


