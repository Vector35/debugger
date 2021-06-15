#include <iostream>
#include <thread>
#include <atomic>
#include "../../src/adapters/debugadapter.h"
#include "../../src/adapters/dbgengadapter.h"
#include "log.h"

void RegisterDisplay(DebugAdapter* debug_adapter)
{
    const auto arch = debug_adapter->GetTargetArchitecture();
    if ( arch.empty() )
        return;

    auto reg = [debug_adapter](std::string reg_name)
    {
        char buf[128]{};

        auto original_name = reg_name;
        reg_name.erase(std::remove(reg_name.begin(), reg_name.end(), ' '), reg_name.end());
        std::sprintf(buf, "%s%s\033[0m=%016llX", Log::Style( 255, 165, 0 ).AsAnsi().c_str(), original_name.c_str(), debug_adapter->ReadRegister(reg_name).m_value);

        return std::string(buf);
    };

    if ( arch == "x86_64" )
    {
        char buf[1024]{};
        std::sprintf(buf, "%s %s %s %s\n%s %s %s %s\n%s %s %s %s\n%s %s %s %s\n%s\n",
                     reg("rax").c_str(), reg("rbx").c_str(), reg("rcx").c_str(), reg("rdx").c_str(),
                     reg("rsi").c_str(), reg("rdi").c_str(), reg("rbp").c_str(), reg("rsp").c_str(),
                     reg(" r8").c_str(), reg(" r9").c_str(), reg("r10").c_str(), reg("r11").c_str(),
                     reg("r12").c_str(), reg("r13").c_str(), reg("r14").c_str(), reg("r15").c_str(),
                     reg("rip").c_str() );

        Log::print(buf);

        const auto register_list = debug_adapter->GetRegisterList();
        if ( std::find(register_list.begin(), register_list.end(), "rflags") != register_list.end() )
            Log::print(reg(" rflags"));
        else if ( std::find(register_list.begin(), register_list.end(), "eflags") != register_list.end())
            Log::print(reg(" eflags"));
    }
}

int main(int argc, const char* argv[])
{
    Log::SetupAnsi();

    try
    {
        auto debug_adapter = new DbgEngAdapter();

        auto as_string = [](bool val) { return val ? "true" : "false"; };

        printf("did attach? : %s\n", as_string(debug_adapter->Attach(/*25244*/std::stoi(argv[1]))));
        //printf("did create? : %s\n", as_string(debug_adapter->Execute("C:\\Windows\\System32\\notepad.exe")));

        /* bp @ ntdll.RtlImageNtHeaderEx, called when ctrl+s in notepad */
        /* using static address for testing */

        for ( const auto& module : debug_adapter->GetModuleList() )
            printf("[%s][%s][0x%llx][0x%llx][%s]\n", module.m_name.c_str(), module.m_short_name.c_str(), module.m_address, module.m_size, module.m_loaded ? "loaded" : "unloaded" );

        printf("adding first breakpoint @ 0x7FFDB2E42B26: \n");
        const auto first_breakpoint = debug_adapter->AddBreakpoint(0x7ff8c4b62b26);
        printf( "   [0x%llx][%lu] -> %s\n", first_breakpoint.m_address, first_breakpoint.m_id, as_string(first_breakpoint.m_is_active));
        printf("adding breakpoints @ 0x7FFDB2E42B26+0x8, 0x7FFDB2E42B26+0x10\n");
        const auto added_breakpoints = debug_adapter->AddBreakpoints({0x7ff8c4b62b26+0x8, 0x7ff8c4b62b26+0x10});
        for ( auto breakpoint : added_breakpoints )
            printf( "   [0x%llx][%lu] -> %s\n", breakpoint.m_address, breakpoint.m_id, as_string(breakpoint.m_is_active));

        printf("list pre removal: \n");
        for ( auto breakpoint : debug_adapter->GetBreakpointList() )
            printf( "   [0x%llx][%lu] -> %s\n", breakpoint.m_address, breakpoint.m_id, as_string(breakpoint.m_is_active));

        printf("removed breakpoints? : %s\n", as_string(debug_adapter->RemoveBreakpoints(added_breakpoints)));

        printf("list post removal: \n");
        for ( auto breakpoint : debug_adapter->GetBreakpointList() )
            printf( "   [0x%llx][%lu] -> %s\n", breakpoint.m_address, breakpoint.m_id, as_string(breakpoint.m_is_active));

        printf("did go? : %s\n", as_string(debug_adapter->Go()));

        RegisterDisplay(debug_adapter);

        printf("press enter to detach\n");
        std::cin.get();
        debug_adapter->Detach();
    }
    catch (const std::exception &except)
    {
        printf("Exception -> %s\n", except.what());
    }
}