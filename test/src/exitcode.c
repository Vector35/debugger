#include <stdio.h>
#include <stdlib.h>

int main(int ac, char **av)
{
	int rc = atoi(av[1]);
	printf("returning %d\n", rc);
	return rc;
}
