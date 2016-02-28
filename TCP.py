from ctypes import *


class TCP(Structure):
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
        pass

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)
