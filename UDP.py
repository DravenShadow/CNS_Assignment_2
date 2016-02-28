from ctypes import *


class UDP(Structure):
    """
    A class to structure an ICMP packet

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

        :param socket_buffer:
        :return:
        """
        pass

    def __new__(self, socket_buffer):
        """

        :param socket_buffer:
        :return:
        """
        return self.from_buffer_copy(socket_buffer)
