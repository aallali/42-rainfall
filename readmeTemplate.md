
### notes
```c
0x080484f4  main
0x00000000  variable1
0x00000000  variable2
0x00000000  function1
0x00000000  function2
```

### 0x08048529 : main() : disassembly
- notebook: (to convert `hex` to `dec` and assign variable names for better reading)
```c

{
    int argc = ebp+0x8
    char **argv = ebp+12

    char *buffer1 = esp+24
    char *buffer2 = esp+156 // ~0x9c

}
```
* __`<0> -> <+8> : prepare stack frame for n function with size 160`__
```c
0x080484f4 <+0>:	push   ebp
0x080484f5 <+1>:	mov    ebp,esp
0x080484f7 <+3>:	push   edi
0x080484f8 <+4>:	push   ebx
0x080484f9 <+5>:	and    esp,0xfffffff0
0x080484fc <+8>:	sub    esp,160 // ~0xa0
```
* __`<+> -> <+> : ...`__
```
...
```
* __`<+192> -> <+198> : exit the program with 0, equivalent to return(0)`__
```c
0x08048f80 <+192>:	mov    eax,0 // eax = 0
0x08048f85 <+197>:	leave  
0x08048f86 <+198>:	ret  // return(0)
```

### Code Prediction 
```c
int main(int argc(ebp+0x8), char **argv(ebp+12)) {

    return (0);
    
}

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
[                   ]
+-------------------+ +28
[                   ]
+-------------------+ +24
[                   ]
+-------------------+ +20
[                   ] 
+-------------------+ +16
[                   ]      <------+ 
+-------------------+ +12         |
[                   ]             |
+-------------------+ +8          |--- 
[                   ]             |  
+-------------------+ +4          |
[                   ]      <------+
+-------------------+ <---ESP
```

### Process of the Exploit
```
..........
```
---
### Solution :

```
..........
```
---

### Ressources :

___[doc1](link)___
___[doc2](link)___
___[doc3](link)___
...
___[docX](link)___