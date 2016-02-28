"""
        Author : Rowland DePree             TCP.py

        A program designed to form the structure of an TCP packet.
"""



from ctypes import *


class TCP(Structure):
    """
    A class to structure an TCP packet

    :param Structure:
    :return:
    """
    _fields_ = [
        ("srcport", c_ushort),
        ("dstport", c_ushort),
        ("seqnum", c_int),
        ("acknum", c_int),
        ("offset", c_ubyte, 4),
        ("reserved", c_ubyte, 3),
        ("ns", c_ubyte, 1),
        ("cwr", c_ubyte, 1),
        ("ece", c_ubyte, 1),
        ("urg", c_ubyte, 1),
        ("ack", c_ubyte, 1),
        ("psh", c_ubyte, 1),
        ("rst", c_ubyte, 1),
        ("syn", c_ubyte, 1),
        ("fin", c_ubyte, 1),
        ("winsize", c_ushort),
        ("checksum", c_ushort),
        ("urgpoint", c_ushort)
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
