default rel

%ifdef OS_IS_WINDOWS
	global WinMain
	extern ExitProcess

	section .text
	WinMain:
%endif

%ifdef OS_IS_LINUX
	global _start
	section .text
	_start:
%endif

%ifdef OS_IS_MACOS
	global start
	section .text
	start:
%endif

	call undiscovered

%ifdef OS_IS_WINDOWS
    mov		rcx, 0
    call    ExitProcess
%endif

%ifdef OS_IS_LINUX
	mov		rdi, 0 ; arg0: status
	mov		rax, 60 ; __NR_exit
	syscall
%endif

%ifdef OS_IS_MACOS
	mov		rax, 0x2000001 ; exit
	mov		rdi, 0
	syscall
%endif

	retn

undiscovered:
	; lea rax, [rip]
	db 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00
	add rax, 6
	; Fake call to rax
	push rax
	retn
	; Unlabelled code that binja does not discover automatically
	mov rax, 0x1234
	mov rbx, 0x5678
	retn

section .data
