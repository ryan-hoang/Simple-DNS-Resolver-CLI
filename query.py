import ctypes


class Query(ctypes.BigEndianStructure):
    _fields_ = [
        ("ID", ctypes.c_uint16, 16),
        ("QR", ctypes.c_uint8, 1),
        ("OPCODE", ctypes.c_uint8, 4),
        ("AA", ctypes.c_uint8, 1),
        ("TC", ctypes.c_uint8, 1),
        ("RD", ctypes.c_uint8, 1),
        ("RA", ctypes.c_uint8, 1),
        ("Z", ctypes.c_uint8, 3),
        ("RCODE", ctypes.c_uint8, 4),
        ("QDCOUNT", ctypes.c_uint16, 16),
        ("ANCOUNT", ctypes.c_uint16, 16),
        ("NSCOUNT", ctypes.c_uint16, 16),
        ("ARCOUNT", ctypes.c_uint16, 16)
    ]