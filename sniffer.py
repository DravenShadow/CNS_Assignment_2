import ctypes
import time
from os import name
from socket import IPPROTO_IP, SOCK_RAW, RCVALL_ON, SIO_RCVALL, IPPROTO_ICMP, RCVALL_OFF, socket, AF_INET, SOCK_DGRAM, \
    IP_HDRINCL
from threading import Thread

from netaddr import IPNetwork, IPAddress

from ICMP import ICMP
from IP import IP

host = "192.168.1.7"

subnet = "192.168.1.0/24"

magic_message = "PYTHONRULES!"


def udp_sender(subnet, magic_message):
    time.sleep(5)
    sender = socket(AF_INET, SOCK_DGRAM)

    for ip in IPNetwork(subnet):
        try:
            sender.sendto(magic_message, ("%s" % ip, 65212))
        except:
            pass


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

                if icmp_header.code == 3 and icmp_header.type == 3:
                    if IPAddress(ip_header.src_address) in IPNetwork(subnet):
                        if raw_buffer[len(raw_buffer) - len(magic_message):] == magic_message:
                            print("Host Up: %s" % ip_header.src_address)
    except KeyboardInterrupt:
        if name == "nt":
            sniffer.ioctl(SIO_RCVALL, RCVALL_OFF)


if __name__ == "__main__":
    t = Thread(target=udp_sender, args=(subnet, magic_message))
    t.start()
    main()
