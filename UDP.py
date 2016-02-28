from ctypes import *


class UDP(Structure):
    _fields_ = [
        ("srcport", c_ushort),
        ("dstport", c_ushort),
        ("len", c_ushort),
        ("checksum", c_ushort)
    ]

    def __init__(self, socket_buffer):
        pass

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)
