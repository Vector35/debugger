#include <iostream>
#include <thread>
#include <atomic>
#include "../../src/adapters/debugadapter.h"
#include "../../src/adapters/dbgengadapter.h"

int main(int argc, const char* argv[])
{
    /* TODO: fix occasional crash when going after removing multiple breakpoints from invalid locations!! */

    try
    {
        auto debug_adapter = new DbgEngAdapter();

        auto as_string = [](bool val) { return val ? "true" : "false"; };

        printf("did attach? : %s\n", as_string(debug_adapter->Attach(25244/*std::stoi(argv[1]))*/)));

        /* bp @ ntdll.RtlImageNtHeaderEx, called when ctrl+s in notepad */
        /* using static address for testing */
        printf("adding first breakpoint @ 0x7FFDB2E42B26: \n");
        const auto first_breakpoint = debug_adapter->AddBreakpoint(0x7FFDB2E42B26);
        printf( "   [0x%llx][%lu] -> %s\n", first_breakpoint.m_address, first_breakpoint.m_id, as_string(first_breakpoint.m_is_active));
        printf("adding breakpoints @ 0x7FFDB2E42B26+0x8, 0x7FFDB2E42B26+0x10\n");
        const auto added_breakpoints = debug_adapter->AddBreakpoints({0x7FFDB2E42B26+0x8, 0x7FFDB2E42B26+0x10});
        for ( auto breakpoint : added_breakpoints )
            printf( "   [0x%llx][%lu] -> %s\n", breakpoint.m_address, breakpoint.m_id, as_string(breakpoint.m_is_active));

        printf("list pre removal: \n");
        for ( auto breakpoint : debug_adapter->GetBreakpointList() )
            printf( "   [0x%llx][%lu] -> %s\n", breakpoint.m_address, breakpoint.m_id, as_string(breakpoint.m_is_active));

        printf("removed breakpoints? : %s\n", as_string(debug_adapter->RemoveBreakpoints({0x7FFDB2E42B26+0x8, 0x7FFDB2E42B26+0x10})));

        printf("list post removal: \n");
        for ( auto breakpoint : debug_adapter->GetBreakpointList() )
            printf( "   [0x%llx][%lu] -> %s\n", breakpoint.m_address, breakpoint.m_id, as_string(breakpoint.m_is_active));

        printf("did go? : %s\n", as_string(debug_adapter->Go()));

        printf("press enter to detach\n");
        std::cin.get();
        debug_adapter->Detach();
    }
    catch (const std::exception &except)
    {
        printf("Exception -> %s\n", except.what());
    }
}