// tests: cmdline arguments, process return value, stdout

#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int i;
	char path[1024] = {};

	printf("Hello, world!\n");
	if (getcwd(path, sizeof(path)))
	{
		printf("cwd: %s\n", path);
	}
	else
	{
		printf("fail to get cwd\n");
	}

	printf("argc: %d\n", argc);
	for(i=0; i<argc; ++i)
		printf("argv[%d]: %s\n", i, argv[i]);

	return 10;
}
