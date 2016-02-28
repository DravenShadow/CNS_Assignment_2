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
    if port_num == 15329:
        freq = 2500
        dur = 1000
        winsound.Beep(freq, dur)
        msgbox("Packet on unencrypted port!", "POSSIBLE ATTACK")


def main():
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

                unencrypted_comm(tcp_header.dstport)

                print("TCP -> Source Port: %d Dest Port: %d" % (tcp_header.srcport, tcp_header.dstport))

            if ip_header.protocol == "UDP":
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset + ctypes.sizeof(UDP)]

                udp_header = UDP(buf)

                unencrypted_comm(udp_header.dstport)

                print("UDP -> Source Port: %d Dest Port: %d" % (udp_header.srcport, udp_header.dstport))

    except KeyboardInterrupt:
        if name == "nt":
            sniffer.ioctl(SIO_RCVALL, RCVALL_OFF)


if __name__ == "__main__":
    main()
