#include <iostream>
#include "../../src/adapters/debugadapter.h"
#include "../../src/adapters/dbgengadapter.h"

int main()
{
    try
    {
        auto debug_adapter = new DbgEngAdapter();
        printf("%x\n", debug_adapter->Execute("C:\\helloworld.exe"));
    }
    catch (const std::exception &except)
    {
        printf("Exception -> %s\n", except.what());
    }
}