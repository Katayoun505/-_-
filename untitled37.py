# -*- coding: utf-8 -*-
"""
Created on Sun Jul 14 14:30:25 2024

@author: UOD Student
"""

import socket
import struct
import binascii

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind(('', 0))
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Function to parse the Ethernet header
def parse_ethernet(data):
    dest_mac, src_mac, protocol = struct.unpack('!6s6s2s', data[:14])
    protocol = binascii.hexlify(protocol)
    dest_mac = binascii.hexlify(dest_mac)
    src_mac = binascii.hexlify(src_mac)
    print(f'Ethernet Header\nDestination MAC: {dest_mac.decode()}\nSource MAC: {src_mac.decode()}\nProtocol: {protocol.decode()}')
    return protocol

# Function to parse the IP header
def parse_ip(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 0xF) * 4
    ttl, proto, src, dest = struct.unpack('!8xB1xB2x4s4s', data[:20])
    src_ip = socket.inet_ntoa(src)
    dest_ip = socket.inet_ntoa(dest)
    print(f'IP Header\nVersion: {version}\nHeader Length: {header_length}\nTTL: {ttl}\nProtocol: {proto}\nSource IP: {src_ip}\nDestination IP: {dest_ip}')
    return proto

# Function to parse the TCP header
def parse_tcp(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('!2H2I1H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    print(f'TCP Header\nSource Port: {src_port}\nDestination Port: {dest_port}\nSequence Number: {sequence}\nAcknowledgment: {acknowledgment}\nOffset: {offset}\nURG: {flag_urg}\nACK: {flag_ack}\nPSH: {flag_psh}\nRST: {flag_rst}\nSYN: {flag_syn}\nFIN: {flag_fin}')

# Function to parse the UDP header
def parse_udp(data):
    src_port, dest_port, length, checksum = struct.unpack('!4H', data[:8])
    print(f'UDP Header\nSource Port: {src_port}\nDestination Port: {dest_port}\nLength: {length}\nChecksum: {checksum}')

# Main loop to capture and analyze network packets
while True:
    packet = s.recvfrom(65565)
    packet = packet[0]

    eth_protocol = parse_ethernet(packet[:14])

    if eth_protocol == '0800':
        ip_protocol = parse_ip(packet[14:34])

        if ip_protocol == 6:
            parse_tcp(packet[34:])
        elif ip_protocol == 17:
            parse_udp(packet[34:])