default rel

%ifdef OS_IS_WINDOWS
	global WinMain

    extern  _GetStdHandle@4
    extern  _WriteConsoleA@20
    extern  _ExitProcess@4

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

	nop
	call bounce
	nop
	call bounce
	nop
	call bounce
	nop
	call bounce
	nop
	call bounce
	nop
	call bounce
	nop
	call bounce
	nop
	call bounce

%ifdef OS_IS_WINDOWS
    push	-11				; STD_OUTPUT_HANDLE
    call    _GetStdHandle@4

    push    0
    push	numCharsWritten
    push	msglen
    push	msg
    push	eax
    call    _WriteConsoleA@20
    add		esp, 0x8

    push	0
    call    _ExitProcess@4
%endif

%ifdef OS_IS_LINUX
	mov		edx, msglen		; arg2: message length
	mov		ecx, msg		; arg1: message
	mov		ebx, 1			; arg0: stdout
	mov		eax, 4			; __NR_write
	int		0x80
	
	mov		ebx, 0			; arg0: status
	mov		eax, 1			; __NR_exit
	int		0x80
%endif

bounce:
	ret

	section .data
msg:		db	"Hello, world!", 0x0a, 0
msglen:	equ	$ - msg
