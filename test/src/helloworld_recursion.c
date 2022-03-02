#include <stdio.h>
#include <stdlib.h>

int fib(int a)
{
	if (a == 0 || a == 1) {
		return 1;
	}
	return fib(a - 1) + fib(a - 2);
}

int main(int ac, char **av)
{
	if (ac == 1) {
		for (int i = 0; i < 50; i ++) {
			printf("The %dth fibonacci number is %d\n", i, fib(i));
		}
	} else {
		printf("The %dth fibonacci number is %d\n", atoi(av[1]), fib(atoi(av[1])));
	}
	return 0;
}
