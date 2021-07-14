; The point here is to test the ability to pass runtime information to analysis.
;
; The simplest case is when a call is encountered in the debugger where the
; destination is not yet an identified function. Just make a function at this
; address.
;
; The second case is when a branch is encountered whose destination is not
; in the set of indirect branches picked up by analysis. This is exercised here
; by having a jump table's check bypassed from another function. Binja picks up
; the legal values of the jump table, but doesn't see that a side flow of
; execution can hop over the constraint for the value that indexes the table.

default rel

	global start
	global function_with_indirect_call
	global function_with_switch
	section .text

start:
	; call case 4 (illegal) of switch by jumping passed check
	lea		rbx, [function_with_switch]
	mov		edi, 431
	call	mapper ; returns 7
	add		rbx, rax
	mov		rcx, 4
	call	rbx

	; call case0, case1 of switch
	mov		rdi, 0
	call	function_with_switch
	mov		rdi, 1
	call	function_with_switch
	mov		rdi, 2
	call	function_with_switch
	mov		rdi, 3
	call	function_with_switch

	; call case 5 (illegal) of switch by jumping passed check
	lea		rbx, [function_with_switch]
	mov		edi, 431
	call	mapper ; returns 7
	add		rbx, rax
	mov		rcx, 5
	call	rbx

	; make some indirect calls
	call	function_with_indirect_call

	; done
	mov		rax, 0x2000001 ; exit
	mov		rdi, 0
	syscall
	ret

function_with_switch:
	; 00000000: 0x48, 0x89, 0xf9
	mov		rcx, rdi				; arg0: 0,1,2,3
	; 00000003: 0x48, 0x83, 0xe1, 0x03
	and		rcx, 0x3
	; 00000007: <--- jumping here bypasses the constraint

	lea		rax, [.jump_table]
	movsx	rdx, dword[rax+rcx*4]
	add		rdx, rax
	jmp		rdx

.case0:
	call	print_00
	jmp		.switch_end

.case1:
	call	print_01
	jmp		.switch_end

.case2:
	call	print_02
	jmp		.switch_end

.case3:
	call	print_03
	jmp		.switch_end

.switch_end:
	ret

.jump_table:
	dd		function_with_switch.case0 - .jump_table
	dd		function_with_switch.case1 - .jump_table
	dd		function_with_switch.case2 - .jump_table
	dd		function_with_switch.case3 - .jump_table
	; these entries should be invisible/illegal to binja because of the "and 3" constraint
	dd		junk + 0x30 - .jump_table
	dd		junk + 0x8e - .jump_table

function_with_indirect_call:
	mov		rcx, 4

.next:
	push	rcx

.test4:
	cmp		rcx, 4
	jne		.test3
	lea		rbx, [print_00]
	jmp		.dispatch

.test3:
	cmp		rcx, 3
	jne		.test2
	lea		rbx, [print_01]
	jmp		.dispatch

.test2:
	cmp		rcx, 2
	jne		.test1
	lea		rbx, [junk]
	mov		rdi, 453 ; -> 48
	call	mapper
	add		rbx, rax
	jmp		.dispatch

.test1:
	cmp		rcx, 1
	lea		rbx, [junk]
	mov		rdi, 163 ; -> 142
	call	mapper
	add		rbx, rax

.dispatch:
	call	rbx

.check:
	pop		rcx
	loop	.next
	ret

; evade data flow
; maps {1,2,3,4,5,6,7,8,9,10,...} -> {1,3,9,27,81,243,220,151,453,341,...}
; forward with pow(3,x,509)
; reverse with brute force [x for x in range(508) if pow(3,x,509) == y]
mapper:
	mov		rcx, rdi	; arg0: number to map
	mov		rax, 1
	jrcxz	.done
.step:
	imul	rax, 3
.reduce:
	cmp		rax, 509
	jl		.next
	sub		rax, 509
	jmp		.reduce
.next:
	loop	.step
.done:
	ret

print_00:
	lea		rsi, [.msg_start]
	lea		rdx, [.done]
	sub		rdx, rsi
	mov		rdi, 1 ; stdout
	mov		rax, 0x2000004 ; write
	syscall
	jmp		.done
.msg_start:
	db		"I'm print_00!", 0x0a
.done:
	ret

print_01:
	mov		rsi, .msg_start
	mov		rdx, .done
	sub		rdx, rsi
	mov		rdi, 1 ; stdout
	mov		rax, 0x2000004 ; write
	syscall
	jmp		.done
.msg_start:
	db		"I'm print_01!", 0x0a
.done:
	ret

print_02:
	mov		rsi, .msg_start
	mov		rdx, .done
	sub		rdx, rsi
	mov		rdi, 1 ; stdout
	mov		rax, 0x2000004 ; write
	syscall
	jmp		.done
.msg_start:
	db		"I'm print_02!", 0x0a
.done:
	ret

print_03:
	mov		rsi, .msg_start
	mov		rdx, .done
	sub		rdx, rsi
	mov		rdi, 1 ; stdout
	mov		rax, 0x2000004 ; write
	syscall
	jmp		.done
.msg_start:
	db		"I'm print_03!", 0x0a
.done:
	ret

junk:
; junk
db 0xEF, 0x3D, 0x53, 0x7C, 0xFB, 0x80, 0x3B, 0x28,
db 0x15, 0xD1, 0xA2, 0xCD, 0x5E, 0x7E, 0xBC, 0xE1,
db 0xC6, 0x1B, 0x63, 0x05, 0xB7, 0xD3, 0xBA, 0x3B,
db 0x39, 0xCA, 0x46, 0xA1, 0x32, 0xD9, 0x8A, 0xB5,
db 0x8F, 0xD6, 0xFA, 0xAE, 0x08, 0x2D, 0xD5, 0x6F,
db 0x1E, 0xD6, 0xB8, 0x72, 0xA9, 0x8D, 0x86, 0xE8

; junk + 0x30
; hidden function
db 0x48, 0x8D, 0x35, 0x18, 0x00, 0x00, 0x00,        ; lea        rsi, [.msg_start]
db 0x48, 0x8D, 0x15, 0x1F, 0x00, 0x00, 0x00,        ; lea        rdx, [.done]
db 0x48, 0x29, 0xF2                                 ; sub        rdx, rsi
db 0xBF, 0x01, 0x00, 0x00, 0x00                     ; mov        rdi, 1 ; stdout
db 0xB8, 0x04, 0x00, 0x00, 0x02                     ; mov        rax, 0x2000004 ; write
db 0x0F, 0x05                                       ; syscall
db 0xEB, 0x0E                                       ; jmp        .done
; .msg_start: "YOU FOUND ME1"
db  0x59, 0x4F, 0x55, 0x20, 0x46, 0x4F, 0x55, 0x4E, 0x44, 0x20, 0x4D, 0x45, 0x31, 0x0a
; .done:
db 0xC3                                             ; ret

; junk + 0x5e
db 0xB4, 0xDE, 0xF0, 0x6B, 0x54, 0x40, 0x08, 0x46,
db 0xF6, 0xAC, 0xDD, 0x82, 0x8C, 0x74, 0x2C, 0x7F,
db 0xBD, 0x0B, 0xC1, 0xBA, 0x12, 0x1F, 0xD0, 0x7C,
db 0x44, 0xFF, 0x43, 0x5F, 0xC6, 0x85, 0xF3, 0x23,
db 0x6B, 0x65, 0x41, 0x2C, 0xB4, 0x4A, 0x5E, 0x24,
db 0x35, 0xBA, 0x57, 0x76, 0x18, 0xAB, 0xE0, 0x51

; junk + 0x8e
; hidden function
db 0x48, 0x8D, 0x35, 0x18, 0x00, 0x00, 0x00,        ; lea        rsi, [.msg_start]
db 0x48, 0x8D, 0x15, 0x1F, 0x00, 0x00, 0x00,        ; lea        rdx, [.done]
db 0x48, 0x29, 0xF2                                 ; sub        rdx, rsi
db 0xBF, 0x01, 0x00, 0x00, 0x00                     ; mov        rdi, 1 ; stdout
db 0xB8, 0x04, 0x00, 0x00, 0x02                     ; mov        rax, 0x2000004 ; write
db 0x0F, 0x05                                       ; syscall
db 0xEB, 0x0E                                       ; jmp        .done
; .msg_start: "YOU FOUND ME2"
db  0x59, 0x4F, 0x55, 0x20, 0x46, 0x4F, 0x55, 0x4E, 0x44, 0x20, 0x4D, 0x45, 0x32, 0x0a
; .done:
db 0xC3                                             ; ret

section .data
	db		"Here's some data.", 0x0a
