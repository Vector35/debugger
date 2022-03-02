#include <stdio.h>

int main(int ac, char **av)
{
	printf("Arguments: \n");
	for (int i = 0; i < ac; i ++) {
		printf("%s\n", av[i]);
	}

	return 0;
}
