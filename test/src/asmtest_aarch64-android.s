// NOTES:
// kernel call: syscall number in x8, args in x0, x1, x2, ...
// syscall number lookup <kernel-source-dir>/include/uapi/asm-generic/unistd.h 
// 
.global	_start

.text

_start:
	nop
	bl		bounce
	nop
	bl		bounce
	nop
	bl		bounce
	nop
	bl		bounce
	nop
	bl		bounce
	nop
	bl		bounce
	nop
	bl		bounce
	nop
	bl		bounce

	mov		x2, msglen		// arg2: message length

	// TODO: explore in detail why this won't work
	//mov		x1, msg			// arg1: message
	adrp	x1, msg
	add		x1, x1, :lo12:msg

	mov		x0, #1			// arg0: stdout
	
	mov		x8, #64			// __NR_write
	svc		#0
	
	mov		x0, #0			// arg0: status
	mov		x8, #94			// __NR_exit
	svc		#0

bounce:
	ret

.data

msg:
	.asciz "Hello, world!\n"

msglen = . - msg

