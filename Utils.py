import struct


def get_platform_pointer_size_bits():
    return struct.calcsize("P") * 8


def Hex(n):
    return hex(n).replace('L', '')
