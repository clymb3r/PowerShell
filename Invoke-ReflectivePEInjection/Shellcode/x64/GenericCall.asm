[SECTION .text]

global _start

_start:
	; Set a var to 1, let PS known exe is exiting
	mov rbx, 0x4141414141414141
	mov [rbx], byte 0x01

	; Call exitthread instead of exitprocess
	sub rsp, 0x20
	and sp, 0xFF00 ; Needed for stack alignment
	mov rbx, 0x4141414141414141
	call rbx
