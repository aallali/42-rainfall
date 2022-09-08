# Rainfall
Rainfall is an iso challenge slightly more complex than [Snow Crash][0]. 
We will have to dive deep into reverse engineering, learn to reconstruct a code, and understand it to detect faults. 
Will you reach the last level? 

#### GDB Commands:
|Command                      | Description |
|:---------------------------:|-------------|
|set disassembly-flavor intel |set the output to  Intel x86 architecture.|
|disass main| diasessmbly the main function|
|info func| get list of functions and their adresses|
|info var| get list of variables and their adresses
|define hook-stop             |define set of gdb commands to execute at once when running the program for debugging when steping with `ni` after run, set the commands u want on each line then write `end` to exit the stdin|
|x/s 0xbf234f |show the content of given address|
|x 0xbf234f | show the stack of the given address
|info registers | show details about the registers (eip, esp, ebp, edx,...)|
|info frame| get details about the stack frame|
|x/10wx $esp|list 10 cases of stack|
|x $eax| get the address inside eax register|

### Flags:
| N°     | Name                   | Flag                        |
|:------:|------------------------|-----------------------------|
| Flag0  | Simple Atoi            | 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a |
| Flag1  | Simple Gets            | 53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77 |
| Flag2  | shellcode /or ret2libc | 492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02 |
| Flag3  | Printf Format (%n exploit)| b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa |
| Flag4  | Printf Format (%n exploit)| 0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a|
| Flag5  | Printf Format 3        | d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31 |
| Flag6  | Overwrite function     | f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d |
| Flag7  | GOT (Global Offset Table)| 5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9 |
| Flag8  | Strings Auth           | c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a |
| Flag9  | CPP overwrite instance |  |
| Bonus0 | GOT 2                  |  |
| Bonus1 | Long int bitwise       |  |
| Bonus2 | Env                    |  |
| Bonus3 | fopen + strcmp         |  |

### Ressources :
| subject     | link          |
|:-----------:|------------------------|
| get buffer offset | [link][1]     |


 
[0]: https://github.com/aallali/Snow-Crash
[1]: https://wiremask.eu/tools/buffer-overflow-pattern-generator/

