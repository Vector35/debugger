// libFuzzer target: fd redirect specification parser.
#include "ptraceengine.h"
#include <string>

using namespace BinaryNinjaDebugger;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	PtraceEngine::FdRedirect redirect;
	std::string error;
	ParseFdRedirect(std::string((const char*)data, size), redirect, error);
	return 0;
}
