#### notes
```
 804988c  m : global variable m
 80484a4  v : function : called in main
 804851a  main : function 
 8048526  main return address
 8048519  main return address
```

##### 0x080484a4 : v() : disassembly
initiate the stack frame of the [v] funciton
```
80484a4 <+0>:	push   ebp
80484a5 <+1>:	mov    ebp,esp
80484a7 <+3>:	sub    esp,0x218
```
Preparation of gets() params
put the ___stdin___ value in ___esp+0x8___
put the ___0x200___ value in ___esp+0x4___
put the ___ebp-0x208___ address in ___esp___ // the buffer
call gets(eax, esp+4, esp+8)

```
80484ad <+9>:	mov    eax,ds:0x8049860
80484b2 <+14>:	mov    DWORD PTR [esp+0x8],eax
80484b6 <+18>:	mov    DWORD PTR [esp+0x4],0x200
80484be <+26>:	lea    eax,[ebp-0x208]
80484c4 <+32>:	mov    DWORD PTR [esp],eax
80484c7 <+35>:	call   0x80483a0 <fgets@plt>
```
print the buffer : ___printf(buffer)___
```
80484cc <+40>:	lea    eax,[ebp-0x208]
80484d2 <+46>:	mov    DWORD PTR [esp],eax
80484d5 <+49>:	call   0x8048390 <printf@plt>
```

compare variable ___m___ if equal to ___0x40 (64)___
```
80484da <+54>:	mov    eax,ds:0x804988c
80484df <+59>:	cmp    eax,0x40
80484e2 <+62>:	jne    0x8048518 <v+116>
```
if __true__ :

- call ___fwrite("Wait what?!", 1, 12, stdout)___
```
80484e4 <+64>:	mov    eax,ds:0x8049880 ---> stdout
80484e9 <+69>:	mov    edx,eax
80484eb <+71>:	mov    eax,0x8048600 ----> "Wait what?!\n"
80484f0 <+76>:	mov    DWORD PTR [esp+0xc],edx
80484f4 <+80>:	mov    DWORD PTR [esp+0x8],0xc ----> 12
80484fc <+88>:	mov    DWORD PTR [esp+0x4],0x1 ----> 1
8048504 <+96>:	mov    DWORD PTR [esp],eax
8048507 <+99>:	call   0x80483b0 <fwrite@plt>
```
- call ___system("/bin/sh")___
```
804850c <+104>:	mov    DWORD PTR [esp],0x804860d ----> "/bin/sh"
8048513 <+111>:	call   0x80483c0 <system@plt>
```
if __false__ :
- leave the program
```
8048518 <+116>:	leave
8048519 <+117>:	ret
```