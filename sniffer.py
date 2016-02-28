"""
        Author: Rowland DePree              sniffer.py

        This is a program designed as an packet sniffer.  It will decode all incoming traffic as well as alert the user if
        the packet is using an port that is marked as dangerous.  The original idea for this code came from Black Hat Python
        by Justin Seitiz.
"""
import ctypes
import winsound
from os import name
from socket import IPPROTO_IP, SOCK_RAW, RCVALL_ON, SIO_RCVALL, IPPROTO_ICMP, RCVALL_OFF, socket, AF_INET, IP_HDRINCL

from easygui import msgbox

from ICMP import ICMP
from IP import IP
from TCP import TCP
from UDP import UDP

host = "192.168.1.7"


def unencrypted_comm(port_num):
    """
    A method used to check if the port is unencrypted and if so alert the user
    :param port_num:
    :return:
    """
    if port_num == 23 or port_num == 8014:
        freq = 2500
        dur = 1000
        winsound.Beep(freq, dur)
        msgbox("Packet on unencrypted port %s \nCheck Attack_Packet.txt file for more info" % port_num,
               "POSSIBLE ATTACK")
        return True
    else:
        return False


def main():
    """
    Main part of the program.  This is where it reads in and decodes all packet traffic
    :return:
    """
    if name == "nt":
        socket_protocol = IPPROTO_IP
    else:
        socket_protocol = IPPROTO_ICMP

    sniffer = socket(AF_INET, SOCK_RAW, socket_protocol)

    sniffer.bind((host, 0))

    sniffer.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

    if name == "nt":
        sniffer.ioctl(SIO_RCVALL, RCVALL_ON)
    try:
        while True:
            raw_buffer = sniffer.recvfrom(65565)[0]

            ip_header = IP(raw_buffer[0:20])

            print("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))

            if ip_header.protocol == "ICMP":
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset + ctypes.sizeof(ICMP)]

                icmp_header = ICMP(buf)

                print("ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code))
            if ip_header.protocol == "TCP":
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset + ctypes.sizeof(TCP)]

                tcp_header = TCP(buf)

                attack = unencrypted_comm(tcp_header.dstport)
                if attack:
                    file = open('Attack_Packet.txt', 'w')
                    file.write("Protocol: TCP")
                    file.write("\tSource: %s" % ip_header.src_address)
                    file.write("\tDestination Port: %s\n" % tcp_header.dstport)
                    file.close()

                print("TCP -> Source Port: %d Dest Port: %d" % (tcp_header.srcport, tcp_header.dstport))

            if ip_header.protocol == "UDP":
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset + ctypes.sizeof(UDP)]

                udp_header = UDP(buf)

                attack = unencrypted_comm(udp_header.dstport)

                if attack:
                    file = open('Attack_Packet.txt', 'w')
                    file.write("Protocol: TCP")
                    file.write("\tSource: %s" % ip_header.src_address)
                    file.write("\tDestination Port: %s\n" % tcp_header.dstport)
                    file.close()

                print("UDP -> Source Port: %d Dest Port: %d" % (udp_header.srcport, udp_header.dstport))

    except KeyboardInterrupt:
        if name == "nt":
            sniffer.ioctl(SIO_RCVALL, RCVALL_OFF)


'''
    Starts the program
'''
if __name__ == "__main__":
    main()
