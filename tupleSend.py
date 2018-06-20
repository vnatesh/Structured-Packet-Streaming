#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct
import re
import readline
import numpy as np

from scapy.all import sendp, send, srp1, get_if_list, get_if_hwaddr
from scapy.all import Packet, hexdump
from scapy.all import Ether, IP, UDP, ShortField, StrFixedLenField, XByteField, IntField
from scapy.all import bind_layers
from scapy.config import conf

from tupleHeader import Tuple


TYPE_IPV4 = 0x800
IP_PROT_UDP = 0x11
DPORT = 0x0da2
# MY_AGE = 0x0000001b; // 27


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


def main():

    if len(sys.argv)<2:
        print 'pass 2 arguments: <destination>'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print "sending on interface %s to %s" % (iface, str(addr))

    tuples = np.random.randint(100, size=(10000, 3))
    valid = 0
    dropped = 0

    s = conf.L2socket(iface=iface)

    for t in tuples: 
        try:
            pkt = Ether(src=get_if_hwaddr(iface), dst='00:00:00:00:01:02', type=TYPE_IPV4)
            pkt = pkt / IP(dst=addr) / UDP(dport=DPORT, sport=random.randint(49152,65535))  
            pkt = pkt / Tuple(age=int(t[0]), height=int(t[1]), weight=int(t[2])) / ' '

            # sendp(pkt, iface=iface, verbose=False)
            s.send(pkt)

        except Exception as error:
            print error


if __name__ == '__main__':
    main()

