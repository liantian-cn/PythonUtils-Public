#!/usr/bin/env python
# -*- coding: utf-8 -*-

import array
import socket
import struct
import sys
import time

from netaddr import *

# total size of data (payload)
ICMP_DATA_STR = 56

# initial values of header variables
ICMP_TYPE = 8
ICMP_CODE = 0
ICMP_CHECKSUM = 0
ICMP_ID = 0
ICMP_SEQ_NR = 0


def get_ping_socket():
    return socket.socket(socket.AF_INET,
                         socket.SOCK_RAW,
                         socket.getprotobyname("icmp"))


def _construct(_id, size):
    """Constructs a ICMP echo packet of variable size
    """

    # size must be big enough to contain time sent
    if size < int(struct.calcsize("d")):
        print(("packetsize to small, must be at least %d" % int(struct.calcsize("d"))))

    # if size big enough, embed this payload
    header = struct.pack('bbHHh', ICMP_TYPE, ICMP_CODE, ICMP_CHECKSUM, ICMP_ID, ICMP_SEQ_NR + _id)
    load = "-- IF YOU ARE READING THIS YOU ARE A NERD! --"

    # space for time
    size -= struct.calcsize("d")

    # construct payload based on size, may be omitted :)
    rest = ""
    if size > len(load):
        rest = load
        size -= len(load)

    # pad the rest of payload
    rest += size * "X"

    # pack
    data = struct.pack("d", time.time()) + rest
    packet = header + data  # ping packet without checksum
    checksum = _in_cksum(packet)  # make checksum

    # construct header with correct checksum
    header = struct.pack('bbHHh', ICMP_TYPE, ICMP_CODE, checksum, ICMP_ID, ICMP_SEQ_NR + _id)

    # ping packet *with* checksum
    packet = header + data

    # a perfectly formatted ICMP echo packet
    return packet


def _in_cksum(packet):
    """THE RFC792 states: 'The 16 bit one's complement of
    the one's complement sum of all 16 bit words in the header.'

    Generates a checksum of a (ICMP) packet. Based on in_chksum found
    in ping.c on FreeBSD.
    """

    # add byte if not dividable by 2
    if len(packet) & 1:
        packet += '\0'

    # split into 16-bit word and insert into a binary array
    words = array.array('h', packet)
    checksum = 0

    # perform ones complement arithmetic on 16-bit words
    for word in words:
        checksum += (word & 0xffff)

    hi = checksum >> 16
    lo = checksum & 0xffff
    checksum = hi + lo
    checksum += checksum >> 16

    return (~checksum) & 0xffff  # return ones complement


def ping_net(net_mask, ping_socket, wait=0):
    ip_net = IPNetwork(net_mask)
    for ip in ip_net.iter_hosts():
        packet = _construct(1, 32)
        ping_socket.sendto(packet, (str(ip), 2))
        time.sleep(wait)


if __name__ == '__main__':
    try:
        net = sys.argv[1]
        ping_net(net, get_ping_socket())
    except IndexError:
        print('Usg: python %s subnet/mask\n' % __file__)
