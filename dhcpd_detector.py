#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Detect dhcp server working status on the network by broadcasting DHCP
discover packet

Created on Mar 27, 2011
Update on May 9, 2014 - ruohan.chen

@author: hassane,
         linxiulei<linxiulei@gmail.com>,
         crhan123@gmail.com<crhan123@gmail.com>
'''

from __future__ import print_function
import socket
import pdb
import struct
import IN
import os
import signal
import errno
import json
import sys
import ConfigParser
from functools import wraps
from array import array
from struct import pack
from uuid import getnode as get_mac
from random import randint
from optparse import OptionParser


class DHCPDiscover:
    def __init__(self, mac, relay_gw = None):
        self.mac = self._getMacInBytes(mac)
        if relay_gw:
            self.relay_gw = self._getIpInBytes(relay_gw)
        else:
            self.relay_gw = None
        self.transactionID = b''
        for i in range(4):
            t = randint(0, 255)
            self.transactionID += struct.pack('!B', t)
        self._server_address = socket.inet_aton('0.0.0.0')

    def _getMacInBytes(self, mac):
        _mac = mac
        while len(_mac) < 12 : # 补齐 12 位 MAC 地址
            _mac = '0' + _mac
        macb = b''
        for i in range(0, 12, 2) :
            m      = int(_mac[i:i + 2], 16)
            macb  += struct.pack('!B', m)
        return macb

    def _getIpInBytes(self, relay_gw):
        ip_slices = relay_gw.split('.')
        ip_bytes = b""
        for i in ip_slices:
            ip_byte = struct.pack("B", int(i))
            ip_bytes += ip_byte
        return ip_bytes

    def buildPacket(self):
        macb = self.mac
        packet = b''
        packet += b'\x01'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0
        packet += self.transactionID       #Transaction ID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
        if self.relay_gw:
            packet += self.relay_gw   #Relay agent IP address: 0.0.0.0
        else:
            packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x01'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        packet += b'\x3d\x06' + macb
        packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'   #End Option
        return packet

    def buildL2Packet(self):
        binary = []
        binary.append('\xff\xff\xff\xff\xff\xff') # dst mac
        binary.append('\x08\x00\x27\x79\xd6\x9c') # src mac
        binary.append('\x08\x00') # prototype
        packet = self.buildPacket()
        packet_len = len(packet)
        binary.append(struct.pack("!BBHHHBB",
         69, #IPv4 + length=5
         0, #DSCP/ECN aren't relevant
         28 + packet_len, #The UDP and packet lengths in bytes
         0, #ID, which is always 0 because we're the origin
         packet_len <= 560 and 0b0100000000000000 or 0, #Flags and fragmentation
         128, #Make the default TTL sane, but not maximum
         0x11, #Protocol=UDP
        ))
        ip_destination = '\xff\xff\xff\xff'
        binary.extend((
         pack("<H", self._ipChecksum(binary[-1], ip_destination)),
         self._server_address,
         ip_destination
        ))
        binary.append(pack("!HH", 68, 67))
        binary.append(pack("!H", packet_len + 8)) #8 for the header itself
        binary.append(pack("<H", self._udpChecksum(ip_destination, binary[-2], binary[-1], packet)))

        #<> Payload
        binary.append(packet)

        return ''.join(binary)

    def buildL3RawPacket(self):
        binary = []
        packet = self.buildPacket()
        packet_len = len(packet)
        binary.append(struct.pack("!BBHHHBB",
         69, #IPv4 + length=5
         0, #DSCP/ECN aren't relevant
         28 + packet_len, #The UDP and packet lengths in bytes
         0, #ID, which is always 0 because we're the origin
         packet_len <= 560 and 0b0100000000000000 or 0, #Flags and fragmentation
         128, #Make the default TTL sane, but not maximum
         0x11, #Protocol=UDP
        ))
        ip_destination = '\xff\xff\xff\xff'
        binary.extend((
         pack("<H", self._ipChecksum(binary[-1], ip_destination)),
         self._server_address,
         ip_destination
        ))
        binary.append(pack("!HH", 68, 67))
        binary.append(pack("!H", packet_len + 8)) #8 for the header itself
        binary.append(pack("<H", self._udpChecksum(ip_destination, binary[-2], binary[-1], packet)))

        #<> Payload
        binary.append(packet)

        return ''.join(binary)


    def _checksum(self, data):
        """
        Computes the RFC768 checksum of ``data``.

        :param sequence data: The data to be checksummed.
        :return int: The data's checksum.
        """
        if sum(len(i) for i in data) & 1:
            data.append('\0')

        words    = array('h', ''.join(data))
        checksum = 0
        for word in words:
            checksum += word & 0xffff
        hi         = checksum >> 16
        low        = checksum & 0xffff
        checksum   = hi + low
        checksum  += (checksum >> 16)
        return ~checksum & 0xffff

    def _ipChecksum(self, ip_prefix, ip_destination):
        """
        Computes the checksum of the IPv4 header.

        :param str ip_prefix: The portion of the IPv4 header preceding the `checksum` field.
        :param str ip_destination: The destination address, in network-byte order.
        :return int: The IPv4 checksum.
        """
        return self._checksum([
         ip_prefix,
         '\0\0', #Empty checksum field
         self._server_address,
         ip_destination,
        ])

    def _udpChecksum(self, ip_destination, udp_addressing, udp_length, packet):
        """
        Computes the checksum of the UDP header and payload.

        :param str ip_destination: The destination address, in network-byte order.
        :param str udp_addressing: The UDP header's port section.
        :param str udp_length: The length of the UDP payload plus header.
        :param str packet: The serialised packet.
        :return int: The UDP checksum.
        """
        return self._checksum([
         self._server_address,
         ip_destination,
         '\0\x11', #UDP spec padding and protocol
         udp_length,
         udp_addressing,
         udp_length,
         '\0\0', #Dummy UDP checksum
         packet,
        ])

class DHCPOffer:
    def __init__(self, data, transID):
        self.data                 = data[42:] # 14 for link header, 20 for ip header 8 for udp header
        self.transID              = transID
        self.offerIP              = ''
        self.nextServerIP         = ''
        self.DHCPServerIdentifier = ''
        self.leaseTime            = ''
        self.router               = ''
        self.subnetMask           = ''
        self.DNS                  = []
        self.unpack()

    def unpack(self):
        _op = None
        if self.data[0:1]:
            _op = struct.unpack("B", self.data[0:1])[0]
        if self.data[4:8] == self.transID and _op == 0x02:
            self.offerIP              = socket.inet_ntoa(self.data[16:20])
            self.nextServerIP         = socket.inet_ntoa(self.data[20:24])
            self.DHCPServerIdentifier = socket.inet_ntoa(self.data[245:249])
            self.leaseTime            = str(struct.unpack('!L', self.data[251:255])[0])
            self.router               = socket.inet_ntoa(self.data[257:261])
            self.subnetMask           = socket.inet_ntoa(self.data[263:267])
            dnsNB                     = struct.unpack("!b",self.data[268])[0]/4
            for i in range(0, 4 * dnsNB, 4):
                self.DNS.append(socket.inet_ntoa(self.data[269 + i :269 + i + 4]))

    def printOffer(self):
        key = ['DHCP Server', 'Offered IP address', 'subnet mask', 'lease time (s)',
                'default gateway']
        val = [self.DHCPServerIdentifier, self.offerIP, self.subnetMask,
                self.leaseTime, self.router]
        for i in range(4):
            print('{0:20s} : {1:15s}'.format(key[i], val[i]), file=sys.stderr)

        print('{0:20s}'.format('DNS Servers') + ' : ', end='', file=sys.stderr)

        if self.DNS:
            print('{0:15s}'.format(self.DNS[0]), file=sys.stderr)

        if len(self.DNS) > 1:
            for i in range(1, len(self.DNS)):
                print('{0:22s} {1:15s}'.format(' ', self.DNS[i]), file=sys.stderr)


class TimeoutError(Exception):
    pass

class Timeout(object):

    def __init__(self, seconds=10):
        self.seconds = seconds
        self.error_message = os.strerror(errno.ETIME)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self._handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.alarm(0)
        return False

    def _handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)


class AliMonitorResult(object):
    def __init__(self):
        self.collection_flag = 1
        self.error_info      = ""
        self.MSG             = []

    def __str__(self):
        return json.dumps({
            "collection_flag": self.collection_flag,
            "error_info": self.error_info,
            "MSG": self.MSG
            })


def detect(dhcps, transactionID, alimonitor_result, timeout, if_name):
    try:
        while True:
            data = dhcps.recv(1024)
            offer = DHCPOffer(data, transactionID)
            if offer.offerIP:
                alimonitor_result.collection_flag = 0
                alimonitor_result.MSG = {"MSG": ("Get Offered DHCP IP %s from server %s via %s" %
                    ( offer.offerIP, offer.DHCPServerIdentifier, if_name )),
                    "status": 0
                    }
                offer.printOffer()
                break

        dhcps.close()   #we close the socket

    except (socket.timeout, TimeoutError) as e:
        alimonitor_result.collection_flag = 0
        alimonitor_result.MSG = {"MSG": ("Timeout by %ss, NO DHCP Offer Detected" % \
                ( timeout )), "status": 1 }
        print(e, file=sys.stderr)

if __name__ == '__main__':
    result = AliMonitorResult()
    section_name = "detector"

    if os.geteuid() != 0:
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)

    parser = OptionParser()
    parser.add_option("-c", "--config", dest="config_file",
            help="config_file")

    (options, args) = parser.parse_args()

    default_args = {"if_name": "eth0", "mac": "08002779d69c", "timeout": "3"}

    config = ConfigParser.ConfigParser(default_args)
    config.add_section(section_name)
    if options.config_file:
        if os.path.isfile(options.config_file):
            config.read(options.config_file)
        else:
            result.collection_flag = 2
            result.error_info = "config file %s doest not exists" % \
                    options.config_file
            print(result)
            sys.exit(2)

    timeout = config.getint(section_name, "timeout")
    if_name = config.get(section_name, "if_name")
    mac     = config.get(section_name, "mac")
    if config.has_option(section_name, "relay_gw"):
        relay_gw = config.get(section_name, "relay_gw")
    else:
        relay_gw = None

    try:
        #defining the socket
        dhcps = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        dhcps.bind((if_name, 3))
        dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #broadcast
        dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        #buiding and sending the DHCPDiscover packet
        discoverPacket = DHCPDiscover(mac=mac, relay_gw=relay_gw)
        dhcps.send(discoverPacket.buildL2Packet())
        print('DHCP Discover sent on device %s waiting for reply...\n' % if_name,
                file=sys.stderr)

        #receiving DHCPOffer packet
        dhcps.settimeout(timeout)

    except socket.error as e:
        result.collection_flag = e.errno
        result.error_info      = e.strerror
        print(result)
        sys.exit(1)

    with Timeout(timeout):
        detect(dhcps, discoverPacket.transactionID, result, timeout, if_name)

    print(result)
