#include <stdio.h>

int main(int ac, char **av)
{
	while (1) {
		int ch = fgetc(stdin);
		if (ch == EOF && (feof(stdin) || ferror(stdin))) {
			break;
		}
		fputc(ch, stdout);
	}

	return 0;
}
