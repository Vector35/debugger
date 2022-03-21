#include <stdio.h>
#include <stdlib.h>

int main()
{
	char buffer[20];
	// Disable the buffering so we can see the output immediately
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("Please type an integer:\n");
	fgets(buffer, sizeof(buffer), stdin);
	int result = atoi(buffer);
	printf("You typed: %d\n", result);
	return 0;
}