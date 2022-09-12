
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
```c
0x08048544 <+35>:	mov    DWORD PTR [esp],8
0x0804854b <+42>:	call   0x80483f0 <malloc@plt> 
0x08048550 <+47>:	mov    edx,eax // edx = malloc(8)
0x08048552 <+49>:	mov    eax,DWORD PTR [esp+28] edx = mOne
0x08048556 <+53>:	mov    DWORD PTR [eax+4],edx // mOne[1] = edx
// mOne[1] =  malloc(8)

```
```c
0x08048559 <+56>:	mov    DWORD PTR [esp],8
0x08048560 <+63>:	call   0x80483f0 <malloc@plt> // malloc(8)
0x08048565 <+68>:	mov    DWORD PTR [esp+24],eax // esp+24 = &eax
// mTwo = malloc(8)
// esp+24 = mTwo
```
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
```c
0x08048588 <+103>:	mov    eax,DWORD PTR [ebp+12] // eax = argv[1]
0x0804858b <+106>:	add    eax,4 
0x0804858e <+109>:	mov    eax,DWORD PTR [eax]
0x08048590 <+111>:	mov    edx,eax // edx = *argv[1]
```
```c
0x08048592 <+113>:	mov    eax,DWORD PTR [esp+28]
0x08048596 <+117>:	mov    eax,DWORD PTR [eax+4]
0x08048599 <+120>:	mov    DWORD PTR [esp+0x4],edx
0x0804859d <+124>:	mov    DWORD PTR [esp],eax
0x080485a0 <+127>:	call   0x80483e0 <strcpy@plt>
// strcpy(mOne[1], argv[1])
```
```c
0x080485a5 <+132>:	mov    eax,DWORD PTR [ebp+12]
0x080485a8 <+135>:	add    eax,8
0x080485ab <+138>:	mov    eax,DWORD PTR [eax]
0x080485ad <+140>:	mov    edx,eax
```
```c
0x080485af <+142>:	mov    eax,DWORD PTR [esp+24]
0x080485b3 <+146>:	mov    eax,DWORD PTR [eax+4]
0x080485b6 <+149>:	mov    DWORD PTR [esp+0x4],edx
0x080485ba <+153>:	mov    DWORD PTR [esp],eax
0x080485bd <+156>:	call   0x80483e0 <strcpy@plt>
// strcpy(mTwo[1], argv[2])
```
```c
0x080485c2 <+161>:	mov    edx,0x80486e9 // "r"
0x080485c7 <+166>:	mov    eax,0x80486eb // "/home/user/level8/.pass"
0x080485cc <+171>:	mov    DWORD PTR [esp+0x4],edx
0x080485d0 <+175>:	mov    DWORD PTR [esp],eax
0x080485d3 <+178>:	call   0x8048430 <fopen@plt> // password = fopen("/home/user/level8/.pass", "r")
```
```c
0x080485d8 <+183>:	mov    DWORD PTR [esp+0x8],eax // password
0x080485dc <+187>:	mov    DWORD PTR [esp+0x4],0x44 // 68
0x080485e4 <+195>:	mov    DWORD PTR [esp],0x8049960 // variable c
0x080485eb <+202>:	call   0x80483c0 <fgets@plt> // fgets(c, 68, password)
```
```c
0x080485f0 <+207>:	mov    DWORD PTR [esp],0x8048703 // "~~"
0x080485f7 <+214>:	call   0x8048400 <puts@plt> // puts("~~")
0x080485fc <+219>:	mov    eax,0x0
```
```c
0x08048601 <+224>:	leave
0x08048602 <+225>:	ret
```
#### stack illustration
```

``` 
---
#### Solution :
---

##### explanation of the exploit:
