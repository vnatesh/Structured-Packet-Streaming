#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
from tupleHeader import Tuple

from pyspark.sql import SparkSession
from pyspark.sql.functions import explode
from pyspark.sql.functions import split



def handle_pkt(pkt):
    if UDP in pkt and pkt[UDP].dport == 3490:
        print
        print (pkt[Tuple].age, pkt[Tuple].height, pkt[Tuple].weight)
    #    hexdump(pkt)
        sys.stdout.flush()


def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()

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


