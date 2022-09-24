
### notes
```c
0x08048ec0  main
```

### 0x08048ec0 : main() : disassembly
- notebook: (to convert `hex` to `dec` and assign variable names for better reading)
```c
{
    int argc = ebp+0x8
    char **argv = ebp+12

    char arg1Execv = esp+16
    char arg2Execv = esp+20

    const uid = esp+24
    const gid = esp+28

    // ebp+0xc ... ebp+12
    // 0x1a7 ... 423
    // 0x10 ... 16
    // 0x14 ... 20
    // 0x16 ... 22
    // 0x18 ... 24
    // 0x1c ... 28
}
```
* __`<0> -> <+6> : prepare stack frame for n function with size 160`__

```c
0x08048ec0 <+0>:	push   ebp
0x08048ec1 <+1>:	mov    ebp,esp
0x08048ec3 <+3>:	and    esp,0xfffffff0
0x08048ec6 <+6>:	sub    esp,32
```
* __`<+9> -> <+20> : call atoi with the first argument (argv[1])`__
* __`<+25> -> <+30> : if atoi(argv[1]) != 423  jump to <main+152>`__
```c
0x08048ec9 <+9>:	mov    eax,DWORD PTR [argv] // eax = argv
0x08048ecc <+12>:	add    eax,4 // eax = argv[1]
0x08048ecf <+15>:	mov    eax,DWORD PTR [eax] // eax = *argv[1]
0x08048ed1 <+17>:	mov    DWORD PTR [esp],eax
0x08048ed4 <+20>:	call   0x8049710 <atoi> // atoi(argv[1])
0x08048ed9 <+25>:	cmp    eax,423
0x08048ede <+30>:	jne    0x8048f58 <main+152>
if (atoi(argv[1] != 423) { jump to main+152 } 
```
* __`<+32> -> <+44> : call strdup with the string "/bin/sh" and put the return in esp+16(arg1Execv)`__
* __`<+48> : put 0 as value in esp+20(arg2Execv) `__
```c
0x08048ee0 <+32>:	mov    DWORD PTR [esp],0x80c5348 // "/bin/sh"
0x08048ee7 <+39>:	call   0x8050bf0 <strdup> // eax = strdup("/bin/sh")
0x08048eec <+44>:	mov    DWORD PTR [arg1Execv],eax 
0x08048ef0 <+48>:	mov    DWORD PTR [arg2Execv],0
arg1Execv = strdup("/bin/sh")
arg2Execv = 0
```
* __`<+56> -> <+61> : call getgid to get the GID value from system and put it in esp+28(gid)`__
```c
0x08048ef8 <+56>:	call   0x8054680 <getegid>
0x08048efd <+61>:	mov    DWORD PTR [gid],eax 
gid = getegid()

```
* __`<+56> -> <+61> : call getuid to get the UID value from system and put it in esp+24(uid)`__
```c
0x08048f01 <+65>:	call   0x8054670 <geteuid>
0x08048f06 <+70>:	mov    DWORD PTR [uid],eax
uid = geteuid()
```
* __`<+74> -> <+97> : call setresgid with 3 params , gid  X 3 : (gid, gid, gid)`__
```c
0x08048f0a <+74>:	mov    eax,DWORD PTR [gid]
0x08048f0e <+78>:	mov    DWORD PTR [esp+8],eax // param3 = gid
0x08048f12 <+82>:	mov    eax,DWORD PTR [gid]
0x08048f16 <+86>:	mov    DWORD PTR [esp+4],eax // param2 = gid
0x08048f1a <+90>:	mov    eax,DWORD PTR [gid] 
0x08048f1e <+94>:	mov    DWORD PTR [esp],eax // param1 = gid
0x08048f21 <+97>:	call   0x8054700 <setresgid>
setresgid(gid, gid, gid)
```
* __`<+102> -> <+125> : call setresuid with 3 params , uid  X 3 : (uid, uid, uid)`__
```c
0x08048f26 <+102>:	mov    eax,DWORD PTR [uid]
0x08048f2a <+106>:	mov    DWORD PTR [esp+8],eax
0x08048f2e <+110>:	mov    eax,DWORD PTR [uid]
0x08048f32 <+114>:	mov    DWORD PTR [esp+4],eax
0x08048f36 <+118>:	mov    eax,DWORD PTR [uid]
0x08048f3a <+122>:	mov    DWORD PTR [esp],eax
0x08048f3d <+125>:	call   0x8054690 <setresuid>
setresuid(uid, uid, uid)
```
* __`<+130> -> <+145> :call execv with "/bin/sh" and [arg1ExecV, arg2ExecV]`__
* __`<+150> : jump to the instruction +192 which is the return step`__

```c
0x08048f42 <+130>:	lea    eax,[esp+16] 
// eax == pgot the address where arg1Execv point to ,
// so eax will point to the next two arguments arg1ExecV and arg2ExecV
0x08048f46 <+134>:	mov    DWORD PTR [esp+4],eax
0x08048f4a <+138>:	mov    DWORD PTR [esp],0x80c5348 // "/bin/sh"
0x08048f51 <+145>:	call   0x8054640 <execv>
0x08048f56 <+150>:	jmp    0x8048f80 <main+192>

execv("/bin/sh", [arg1Execv, arg2Execv])
jump to return
```
* __`<+152> -> <+187> : call fwrite with params set in the stack by order fwrite(esp, esp+4, esp+8, esp+12)`__
```c
0x08048f58 <+152>:	mov    eax,ds:0x80ee170 // stderr
0x08048f5d <+157>:	mov    edx,eax
0x08048f5f <+159>:	mov    eax,0x80c5350 // "No !\n"
0x08048f64 <+164>:	mov    DWORD PTR [esp+12],edx  // param4 = stderr
0x08048f68 <+168>:	mov    DWORD PTR [esp+8],5  // param3 = 5
0x08048f70 <+176>:	mov    DWORD PTR [esp+4],1 // param2 = 1
0x08048f78 <+184>:	mov    DWORD PTR [esp],eax // param1 = "No !\n"
0x08048f7b <+187>:	call   0x804a230 <fwrite>
fwrite("No !\n", 1, 5, stderr)
```
* __`<+192> -> <+198> : exit the program with 0 equivalent to return(0)`__
```c
0x08048f80 <+192>:	mov    eax,0 // eax = 0
0x08048f85 <+197>:	leave  
0x08048f86 <+198>:	ret  // return(0)
```

### Stack Illustration
```shell
+-------------------+ 
[      **argv       ]
+-------------------+ +12
[        argc       ]
+-------------------+ +8
[ret addr (OLD_EIP) ]
+-------------------+ +4
[      OLD_EBP      ]
+-------------------+ <---EBP
[and esp,0xfffffff0 ] <--- stack alignement 
+-------------------+
[                   ]
+-------------------+ +32
[        GID        ]
+-------------------+ +28
[        UID        ]
+-------------------+ +24
[ strdup("/bin/sh") ]
+-------------------+ +20
[          0        ] 
+-------------------+ +16
[       stderr      ]      <------+ 
+-------------------+ +12         |
[         5         ]             |
+-------------------+ +8          |--- this is set after this line 0x08048f58 <+152>
[         1         ]             |  
+-------------------+ +4          |
[      "No !\n"     ]      <------+
+-------------------+ <---ESP
```


### Code Prediction 
```c
int main(int argc(ebp+0x8), char **argv(ebp+12)) {

    if (atoi(argv[1] != 423){ 
        fwrite("No !\n", 1, 5, stderr)
    }
    else {

        arg1Execv = strdup("/bin/sh")
        arg2Execv = 0

        gid = getegid()
        uid = geteuid()

        setresgid(gid, gid, gid)
        setresuid(uid, uid, uid)

        execv("/bin/sh", [arg1Execv, arg2Execv])

    }
    return (0);
}

```
### Process of the Exploit
- from the ASM analyse we come out with this result :
-- the program take one argument and parse it to intiger then compare it to `423`
-- if argument == 423 : execute shell
-- if not : print `"No !\n"` and exit program

---
### Solution :
simpyl we give 423 as argument to ./level0
```
level0@RainFall:~$ ./level0 423
$ pwd
/home/user/level0
$ whoami                
level1
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
$ 
```

---


### Ressources :

N/A