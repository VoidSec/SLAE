; Paolo Stagno aka [VoidSec](https://voidsec.com)
; SLAE-1511

section .text
 global _start
  _start:
   xor rdx, rdx				; NULL, 3rd EXECVE’s parameter & to push 0 on the stack
   push "-aal" 				; Push 2nd argument (string) to the stack
   mov rax, rsp 			; Load addr of the 2nd argument
   mov rcx, "/bin//ls"		; Load the file name (string)
   push rdx					; NULL character
   push rcx					; Load file name (string) to the stack
   mov rdi, rsp				; Load addr of "/bin//ls". 1st member of argv & 1st execve param 
							; Creating ARGV Structure
   push rdx					; ARGV terminated by NULL character
   push rax					; 2nd arg is a pointer to "-aal"
   push rdi					; 1st arg is a pointer to "/bin//ls"
   mov rsi, rsp				; Load addr of ARGV into the 2nd parameter of EXECVE
   xor rax, rax				; Clean RAX
   mov al, 59				; EXECVE syscall number
   syscall					; Execute syscall

; ------------------------------------------------
; Execve Syscall:
; >	*filename	- RDI = /bin//ls
; >	Argv[] 		- RSI = /bin//ls -aal
; >	Envp[] 		- RDX = 0000 0000

; Usage order during syscall/function call: rdi, rsi, rdx, rcx, r8d, r9d
; ------------------------------------------------
; STACK
; >	10: -aal
; >	9: 0000 0000
; >	8: /bin//ls
; >	7: 0000 0000
; >	6: Stack10
; >	5: Stack8
; ------------------------------------------------
; Registers step by step
; 1.	Rdx = 0000 0000
; 2.	Rax = -> stack10
; 3.	Rcx = /bin//ls
; 4.	Rdi = -> stack8
; 5.	Rsi = -> stack5
; 6.	Rax = 0000 0000
; 7.	Rax = 0059 0000
; ------------------------------------------------
