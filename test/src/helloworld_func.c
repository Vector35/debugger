#include <stdio.h>

int hello(int a)
{
	printf("Hello, world! %d\n", a);
	return a;
}

int main(int ac, char **av)
{
	hello(0);
	hello(1);
	hello(2);
	hello(3);
	return 0;
}
