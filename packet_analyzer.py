import socket, sys
from struct import *

ethernet_header_length = 14
ip_header_length = tcp_header_length = icmp_header_length = 0

def get_hex_address (ethernet_header) :
  hex_address = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]),
          ord(a[1]),
          ord(a[2]),
          ord(a[3]),
          ord(a[4]),
          ord(a[5]))
  return hex_address

try:
    s = socket.socket( socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.ntohs(0x0003))
except socket.error , message:
    print 'Socket could not be created. Error Code : %s %s ' %\
        (str(message[0]), message[1])
    sys.exit()


def parse_ethernet_header(packet):
    ethernet_header = packet[:ethernet_header_length]
    ethernet_header = unpack('!6s6sH', ethernet_header)
    ethernet_protocol = socket.ntohs(ethernet_header[2])
    print("========Ethernet       Packet==============================")
    print('Destination MAC : ' + get_hex_address(packet[0:6]) +\
    ' Source MAC : ' + get_hex_address(packet[6:12]) +\
    ' Protocol : ' + str(ethernet_protocol))

    if ethernet_protocol == 8:
        parse_ip_header(packet)
    else :
        print("Parsing supported for only IP packets")

def parse_ip_header(packet):
    ip_header = packet[ethernet_header_length:20 + ethernet_header_length]

    ip_header = unpack('!BBHHHBBH4s4s' , ip_header)
    ttl = iph[5]
    ip_protocol = iph[6]
    source_addr = socket.inet_ntoa(iph[8]);
    dest_addr = socket.inet_ntoa(iph[9]);
    print("============IP Packet==========================")
    print(' TTL : ' + str(ttl) + ' Protocol : ' +\
    str(protocol) + ' Source Address : ' +\
    str(source_addr) + ' Destination Address : ' + str(dest_addr)
    if protocol == 6:
        parse_tcp_header(packet, ip_header_length)
    elif protocol == 1:
        parse_icmp_header(packet, ip_header_length)
    elif protocol == 17:
        parse_udp_header(packet, ip_header_length)
    else:
        print("Couldn't parse")

def parse_tcp_header(packet, ip_header_length):
    skip = ip_header_length + ethernet_header_length
    tcp_header = packet[skip : skip+20]
    tcp_header = unpack('!HHLLBBHHH' , tcp_header)
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    print("===============TCP PACKET=======================")
    print 'Source Port : ' + str(source_port) + ' Dest Port : ' +\
    str(dest_port) + ' Sequence Number : ' + str(sequence) +\
    ' Acknowledgement : ' + str(acknowledgement))
    skip = ethernet_length + ip_header_length + tcp_header_length * 4
    data_size = len(packet) - skip
    #get data from the packet
    data = packet[skip:]
    print('Data : ' + data)

def parse_icmp_header(packet, ip_header_length):
    skip = ip_header_length + ethernet_header_length
    icmp_header__length = 4
    icmp_header = packet[skip:skip+4]
    icmph = unpack('!BBH' , icmp_header)
    icmp_type = icmph[0]
    code = icmph[1]
    checksum = icmph[2]
    print("==========ICMP PACKET==============")
    print('Type : ' + str(icmp_type) + ' Code : ' +\
    str(code) + ' Checksum : ' + str(checksum))
    skip = eth_length + ip_header_length + icmp_header_length
    data_size = len(packet) - skip
    #get data from the packet
    data = packet[skip:]
    print('Data : ' + data)


# Till the end of world keep receiving packets
while True:
    packet = s.recvfrom(65565)
    #get first packet from tuple and process
    packet = packet[0]
    parse_ethernet_header(packet)