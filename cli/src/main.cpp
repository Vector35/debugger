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

    //0x7ff8c4b62b26
    try
    {
        auto debug_adapter = new DbgEngAdapter();
        if (!debug_adapter->Attach(std::stoi(argv[1])))
            return -1;

        std::thread( [&]{
            while ( true )
                if ( GetAsyncKeyState(VK_F2) & 1 )
                    debug_adapter->BreakInto();
        }).detach();

        char input_buf[256];
        const auto red_style = Log::Style(255, 90, 90).AsAnsi();
        const auto white_style = Log::Style(255, 255, 255).AsAnsi();
        while ( Log::print("%sBINJA%sDBG%s> ", red_style.c_str(), white_style.c_str(), red_style.c_str() ) && std::cin.getline(input_buf, sizeof(input_buf)) )
        {
            auto input = std::string(input_buf);

            if (input == "reg")
                RegisterDisplay(debug_adapter);

            if (auto loc = input.find("bp ");
                    loc != std::string::npos)
                debug_adapter->AddBreakpoint(std::stoull(input.substr(loc + 3).c_str(), nullptr, 16));

            if (auto loc = input.find("bpr ");
                    loc != std::string::npos)
                debug_adapter->RemoveBreakpoint(DebugBreakpoint( std::stoull(input.substr(loc + 4).c_str(), nullptr, 16 )));

            if ( input == "bpl" )
            {
                Log::print("%i breakpoint[s] set\n", debug_adapter->GetBreakpointList().size());
                for (const auto& breakpoint : debug_adapter->GetBreakpointList())
                    Log::print("    breakpoint[%i] @ 0x%llx is %s%s\n", breakpoint.m_id, breakpoint.m_address,
                               breakpoint.m_is_active ? Log::Style(0, 255, 0).AsAnsi().c_str() : Log::Style(255, 0, 0).AsAnsi().c_str(),
                               breakpoint.m_is_active ? "active" : "not active");
            }

            if ( input == "sr" )
                Log::print<Log::Warning>( "stop reason : %x\n", debug_adapter->StopReason() );

            if ( input == "es" )
                Log::print<Log::Info>( "execution status : %x\n", debug_adapter->ExecStatus() );

            if (input == "go")
                debug_adapter->Go();

            if (input == "force_go")
            {
                const auto ip_name = debug_adapter->GetTargetArchitecture() == "x86" ? "eip" : "rip";
                const auto ip = debug_adapter->ReadRegister(ip_name).m_value;
                Log::print<Log::Warning>( "setting old ip[0x%llx] to [0x%llx]\n", ip, ip + 1 );
                debug_adapter->WriteRegister(ip_name, ip + 1);
                if (debug_adapter->ReadRegister(ip_name).m_value == ip + 1 )
                    Log::print<Log::Success>( "set ip to [0x%llx]\n", ip + 1 );
                debug_adapter->Go();
            }

            if (input == "so")
                debug_adapter->StepOver();

            if (input == "detach")
            {
                debug_adapter->Detach();
                break;
            }
        }
    }
    catch (const std::exception &except)
    {
        printf("Exception -> %s\n", except.what());
    }
}