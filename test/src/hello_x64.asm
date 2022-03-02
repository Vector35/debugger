default rel

%ifdef OS_IS_WINDOWS
	global WinMain
	extern ExitProcess, GetStdHandle, WriteConsoleA

	section .bss
	numCharsWritten               resd 1

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

%ifdef OS_IS_WINDOWS
    mov		ecx, -11				; STD_OUTPUT_HANDLE
    call    GetStdHandle

    push    0
    mov		r9, numCharsWritten
    mov		r8, msg.len
    mov		rdx, msg
    mov		rcx, rax
    call    WriteConsoleA
    add		rsp, 0x8

    mov		rcx, 0
    call    ExitProcess

%else
	lea		rsi, [msg]
	mov		rdx, msg.len
	mov		rdi, 1 ; stdout
%endif

%ifdef OS_IS_LINUX
	mov		rax, 1 ; write
	syscall
	mov		rdi, 0 ; arg0: status
	mov		rax, 60 ; __NR_exit
	syscall
%endif

%ifdef OS_IS_MACOS
	mov		rax, 0x2000004 ; write
	syscall
	mov		rax, 0x2000001 ; exit
	mov		rdi, 0
	syscall
%endif

msg:
	db		"Hello, world!", 0x0a
	.len:   equ	$ - msg
