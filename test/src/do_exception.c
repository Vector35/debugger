#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*PFOO)(void);

int main(int ac, char **av)
{
	printf("start\n");

	if(!strcmp(av[1], "segfault")) {
		printf("accessing from 0xDEADBEEF\n");
		return *(int *)0xDEADBEEF;
	}

	if(!strcmp(av[1], "illegalinstr")) {
		#if defined(ARCH_IS_X64)
		printf("X64 bad instruction\n");
		unsigned char buf[] = {
			0x66, 0x06,	// push es on x86, invalid in x64
			0x0f, 0xb9,	// ud2b
			0x0f, 0x0b,	// ud2
			0xfe, 0xf0,
			0x90,
			0x90
		#elif defined(ARCH_IS_X86)
		printf("X86 bad instruction\n");
		unsigned char buf[] = {
			0x0f, 0x0b // ud2
		#elif defined(ARCH_IS_ARMV7)
		printf("ARMV7 bad instruction\n");
		unsigned char buf[] = {
			0xf0, 0xde, 0xf0, 0xe7, // little endian 0xe7f0def0
			0xe7, 0xf0, 0xde, 0xf0 // big endian
		#elif defined(ARCH_IS_AARCH64)
		printf("AARCH64 bad instruction\n");
		unsigned char buf[] = {
			// https://developer.arm.com/docs/ddi0596/a/a64-base-instructions-alphabetic-order/udf-permanently-undefined
			0x00, 0x00, 0x00, 0x00
		#endif
		};

		PFOO bar = (PFOO)buf;
		return bar();
	}

	if(!strcmp(av[1], "divzero")) {
		printf("dividing by zero\n");
		int foo = 31337;
		float result = 0;
		int i = 9;
		while(i >= 0) {
			printf("dividing by %d\n", i);
			result = foo/i;
			i -= 1;
			printf("result is: %f\n", result);
		}
	}

	printf("end\n");
	return 0;
}
