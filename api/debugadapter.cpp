#include "debugadapter.h"

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;

DebugAdapter::DebugAdapter(BinaryNinja::BinaryView *data)
{
	BNDebuggerCustomDebugAdapter adapter;
	adapter.context = this;
	adapter.init = InitCallback;
}


DebugAdapter::~DebugAdapter()
{

}


bool DebugAdapter::InitCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->Init();
}
