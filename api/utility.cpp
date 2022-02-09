#include "debuggerapi.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;
using namespace std;


bool DebugModule::IsSameBaseModule(const std::string& module1, const std::string& module2)
{
	return BNDebuggerIsSameBaseModule(module1.c_str(), module2.c_str());
}
