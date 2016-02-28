"""
        Author : Rowland DePree             ICMP.py

        A program designed to form the structure of an ICMP packet
"""

from ctypes import *


class ICMP(Structure):
    """
    A class to structure an ICMP packet

    :param Structure:
    :return:
    """
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("unused", c_ushort),
        ("next_hop_mtu", c_ushort)
    ]

    def __init__(self, socket_buffer):
        """
        Constructor
        :param socket_buffer:
        :return:
        """
        pass

    def __new__(self, socket_buffer):
        """
        Forms the structure of the packet from the parameter
        :param socket_buffer:
        :return:
        """
        return self.from_buffer_copy(socket_buffer)
