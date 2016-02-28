"""
        Author : Rowland DePree             UDP.py

        A program designed to form the structure of an UDP packet.  The original idea for this code came from Black Hat Python
        by Justin Seitiz.
"""


from ctypes import *


class UDP(Structure):
    """
    A class to structure an UDP packet

    :param Structure:
    :return:
    """
    _fields_ = [
        ("srcport", c_ushort),
        ("dstport", c_ushort),
        ("len", c_ushort),
        ("checksum", c_ushort)
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
