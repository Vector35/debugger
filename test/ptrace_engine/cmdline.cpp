// Prints the arguments that the command line in argv[1] splits into, each followed by a NUL, or exits with 3 if a quote or a
// backslash is left open. The tests compare it with what sh makes of the same text.
#include "ptracecmdline.h"
#include <cstdio>

int main(int argc, char** argv)
{
	if (argc != 2)
		return 2;
	auto arguments = BinaryNinjaDebugger::ParseCommandLineArguments(argv[1]);
	if (!arguments)
		return 3;
	for (const auto& argument : *arguments)
		fwrite(argument.c_str(), 1, argument.size() + 1, stdout);
	return 0;
}
