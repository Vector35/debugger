#include <iostream>
#include <thread>
#include <atomic>
#include "../../src/debugadapter.h"
#ifdef WIN32
#include "../../src/adapters/dbgengadapter.h"
#else
#include "../../src/adapters/gdbadapter.h"
#endif
#include "log.h"
#include <binaryninjacore.h>
#include <binaryninjaapi.h>
#include <lowlevelilinstruction.h>
#include <mediumlevelilinstruction.h>
#include <highlevelilinstruction.h>

using namespace BinaryNinja;

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

    auto reg32 = [debug_adapter](std::string reg_name)
    {
        char buf[128]{};

        auto original_name = reg_name;
        reg_name.erase(std::remove(reg_name.begin(), reg_name.end(), ' '), reg_name.end());
        std::sprintf(buf, "%s%s\033[0m=%018llX", Log::Style( 255, 165, 0 ).AsAnsi().c_str(), original_name.c_str(), debug_adapter->ReadRegister(reg_name).m_value);

        return std::string(buf);
    };

    auto reg16 = [debug_adapter](std::string reg_name)
    {
        char buf[128]{};

        auto original_name = reg_name;
        reg_name.erase(std::remove(reg_name.begin(), reg_name.end(), ' '), reg_name.end());
        std::sprintf(buf, "%s%s\033[0m=%014llX", Log::Style( 255, 165, 0 ).AsAnsi().c_str(), original_name.c_str(), debug_adapter->ReadRegister(reg_name).m_value);

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
    else if ( arch == "x86" )
    {
        char buf[1024]{};
        std::sprintf(buf, "%s %s %s %s\n%s %s %s %s\n%s %s\n",
                     reg32("eax").c_str(), reg32("ebx").c_str(), reg32("ecx").c_str(), reg32("edx").c_str(),
                     reg32("esi").c_str(), reg32("edi").c_str(), reg32("ebp").c_str(), reg32("esp").c_str(),
                     reg32("eip").c_str(), reg32("eflags").c_str() );

        Log::print(buf);
    }
    else
    {
        Log::print<Log::Error>("unknown architecture\n");
    }
}

void DisasmDisplay(DebugAdapter* debug_adapter, const std::uint32_t reg_count)
{
    using namespace BinaryNinja;

    std::vector<std::string> disasm_strings{};
    std::vector<std::string> llil_strings{};
    std::vector<std::string> mlil_strings{};
    std::vector<std::string> hlil_strings{};

    std::uintptr_t instruction_increment{};
    for (std::uint32_t steps{}; steps < reg_count; steps++)
    {
        const auto instruction_offset = debug_adapter->GetInstructionOffset() + instruction_increment;
        if (!instruction_offset)
            return;

        const auto architecture = Architecture::GetByName(debug_adapter->GetTargetArchitecture());
        if (!architecture)
            return;

        const auto data = debug_adapter->ReadMemoryTy<std::array<std::uint8_t, 50>>(instruction_offset);
        if (!data.has_value())
            return;

        const auto data_value = data.value();
        std::size_t size{data_value.size()};
        std::vector<InstructionTextToken> instruction_tokens{};
        if (!architecture->GetInstructionText(data.value().data(), instruction_offset, size, instruction_tokens)) {
            printf("failed to disassemble\n");
            return;
        }

        instruction_increment += size;

        auto data_buffer = DataBuffer(data_value.data(), size);
        Ref<BinaryData> bd = new BinaryData(new FileMetadata(), data_buffer);
        Ref<BinaryView> bv;
        for (const auto& type : BinaryViewType::GetViewTypes())
            if (type->IsTypeValidForData(bd) && type->GetName() == "Raw") {
                bv = type->Create(bd);
                break;
            }

        bv->UpdateAnalysisAndWait();

        Ref<Platform> plat = nullptr;
        auto arch_list = Platform::GetList();
        for ( const auto& arch : arch_list ) {
            constexpr auto os =
            #ifdef WIN32
            "windows";
            #else
            "linux";
            #endif

            using namespace std::string_literals;
            if ( arch->GetName() == os + "-"s + debug_adapter->GetTargetArchitecture() )
            {
                plat = arch;
                break;
            }
        }

        bv->AddFunctionForAnalysis(plat, 0);

        for ( const auto& instruction : instruction_tokens )
            disasm_strings.push_back(instruction.text);
        disasm_strings.emplace_back("\n");

        for (auto& func : bv->GetAnalysisFunctionList())
        {
            Ref<HighLevelILFunction> hlil = func->GetHighLevelIL();
            Ref<MediumLevelILFunction> mlil = func->GetMediumLevelIL();
            Ref<LowLevelILFunction> llil = func->GetLowLevelIL();
            if (!hlil || !mlil || !llil)
                continue;

            for (auto& llil_block : llil->GetBasicBlocks())
            {
                for (std::size_t llil_index = llil_block->GetStart(); llil_index < llil_block->GetEnd(); llil_index++)
                {
                    const auto current_llil_instruction = llil->GetInstruction(llil_index);
                    std::vector<InstructionTextToken> llil_tokens;
                    if ( llil->GetInstructionText(func, func->GetArchitecture(), llil_index, llil_tokens) )
                    {
                        bool did_fail = false;
                        for (const auto& token : llil_tokens)
                            if ( token.text != "undefined" )
                                llil_strings.push_back(token.text);
                            else
                                did_fail = true;

                        if ( !did_fail )
                            llil_strings.emplace_back("\n");
                    }
                }
            }

            for (auto& mlil_block : mlil->GetBasicBlocks())
            {
                for (std::size_t mlil_index = mlil_block->GetStart(); mlil_index < mlil_block->GetEnd(); mlil_index++)
                {
                    const auto current_mlil_instruction = mlil->GetInstruction(mlil_index);
                    std::vector<InstructionTextToken> mlil_tokens;
                    if ( mlil->GetInstructionText(func, func->GetArchitecture(), mlil_index, mlil_tokens) )
                    {
                        bool did_fail = false;
                        for (const auto& token : mlil_tokens)
                            if ( token.text != "undefined" )
                                mlil_strings.push_back(token.text);
                            else
                                did_fail = true;

                        if ( !did_fail )
                            mlil_strings.emplace_back("\n");
                    }
                }
            }

            for (auto& hlil_block : hlil->GetBasicBlocks())
            {
                for (std::size_t hlil_index = hlil_block->GetStart(); hlil_index < hlil_block->GetEnd(); hlil_index++)
                {
                    const auto current_hlil_instruction = hlil->GetInstruction(hlil_index);

                    bool did_fail = false;
                    auto instruction_text = hlil->GetInstructionText(hlil_index);
                    for ( const auto& text : instruction_text )
                        for ( const auto& token : text.tokens )
                            if ( token.text != "undefined" )
                                hlil_strings.push_back(token.text);
                            else
                                did_fail = true;

                    if ( !did_fail )
                        hlil_strings.emplace_back("\n");
                }
            }

            //debug_adapter->StepOver();
        }
    }

    Log::print("%s[disasm]\n", Log::Style(255, 180, 190).AsAnsi().c_str());
    for ( const auto& disasm : disasm_strings )
        Log::print<Log::Info>(disasm);

    Log::print("%s[llil]\n", Log::Style(255, 180, 190).AsAnsi().c_str());
    for ( const auto& llil : llil_strings )
        Log::print<Log::Success>(llil);

    Log::print("%s[mlil]\n", Log::Style(255, 180, 190).AsAnsi().c_str());
    for ( const auto& mlil : mlil_strings )
        Log::print<Log::Warning>(mlil);

    Log::print("%s[hlil]\n", Log::Style(255, 180, 190).AsAnsi().c_str());
    for ( const auto& hlil : hlil_strings )
        Log::print<Log::Error>(hlil);
}

int main(int argc, const char* argv[])
{
    LogToStdout(WarningLog);

    if (argc < 2)
    {
        LogError("usage: %s <debuggee_path>", argv[0]);
        return 0;
    }

    Log::SetupAnsi();

    /* reminder to set plugins directory manually to the proper path
     * windows -> R"(C:\Users\admin\AppData\Local\Vector35\BinaryNinja\plugins)"
     * linux -> R"(/home/user/Desktop/binaryninja/plugins)"
     * macos -> */

    SetBundledPluginDirectory(R"(/mnt/F/Software/binaryninja/plugins)");
    InitPlugins();

    try
    {
        auto debug_adapter = new
        #ifdef WIN32
        DbgEngAdapter();
        #else
        GdbAdapter();
        #endif

        if (!debug_adapter->Execute(argv[1]))
        {
            LogError("failed to execute %s\n", argv[1]);
            return -1;
        }

        std::thread( [&]{
#ifdef WIN32
            while ( true )
                if ( GetAsyncKeyState(VK_F2) & 1 )
                    debug_adapter->BreakInto();
#else
            //std::this_thread::sleep_for(std::chrono::milliseconds(5000));
            //debug_adapter->BreakInto();
        /* TODO: key presses on not windows */
#endif
        }).detach();

        char input_buf[256];
        const auto red_style = Log::Style(255, 90, 90).AsAnsi();
        const auto white_style = Log::Style(255, 255, 255).AsAnsi();
        while ( Log::print("%sBINJA%sDBG%s> ", red_style.c_str(), white_style.c_str(), red_style.c_str() ) && std::cin.getline(input_buf, sizeof(input_buf)) )
        {
            auto input = std::string(input_buf);
            if ( input == "help" )
            {
                const auto bar_style = Log::Style(200, 180, 190).AsAnsi();
                const auto blue_style = Log::Style(0, 255, 255).AsAnsi();

                constexpr auto help_string = "%s===== %sBINJA%sDBG%s %s=====\n";
                Log::print(help_string, bar_style.c_str(), red_style.c_str(), white_style.c_str(), red_style.c_str(), bar_style.c_str());

                auto print_arg = [&](const std::string& cmd, const std::string& description, const std::string& args = "")
                {
                    Log::print("%s| %s%s%s, %s%s", bar_style.c_str(), blue_style.c_str(), cmd.c_str(), white_style.c_str(), white_style.c_str(), description.c_str());
                    if ( !args.empty() )
                        Log::print(" -> takes %s%s", red_style.c_str(), args.c_str());
                    Log::print("\n");
                };

                print_arg("[F2 KEY]", "breaks in");
                print_arg(".", "invokes debugger backend", "command");
                print_arg("lt", "list all threads");
                print_arg("lm", "list all modules");
                print_arg("bpl", "list all breakpoints");
                print_arg("reg", "display registers");
                print_arg("disasm", "disassemble & lift instructions", "instruction count");
                print_arg("sr", "display stop reason");
                print_arg("es", "display execution status");
                print_arg("bp", "add a breakpoint", "address (hex)");
                print_arg("bpr", "remove a breakpoint", "address (hex)");
                print_arg("go", "go");
                print_arg("force_go", "increment instruction pointer and go");
                print_arg("so", "step over");
                print_arg("sot", "step out");
                print_arg("si", "step into");
                print_arg("st", "step to", "address (hex)");
                print_arg("ts", "set active thread", "thread id");
                print_arg("detach", "detach debugger");
            }
            if ( input[0] == '.' )
            {
                debug_adapter->Invoke(input.substr(1));
            }
            else if ( input == "lm" )
            {
                Log::print<Log::Success>( "[modules]\n" );
                for ( const auto& module : debug_adapter->GetModuleList() )
                    Log::print<Log::Info>( "[%s, %s] %s @ 0x%llx with size 0x%x\n", module.m_name.c_str(), module.m_short_name.c_str(), module.m_loaded ? "is loaded" : "was unloaded", module.m_address, module.m_size );
            }
            else if ( input == "lt" )
            {
                Log::print<Log::Success>( "[threads]\n" );
                for ( const auto& thread : debug_adapter->GetThreadList() )
                    Log::print<Log::Info>( "[%i] tid %i\n", thread.m_index, thread.m_tid );
            }
            else if (input == "reg")
            {
                RegisterDisplay(debug_adapter);
            }
            else if (auto loc = input.find("ts ");
                    loc != std::string::npos)
            {
                auto thread_id = std::stoul(input.substr(loc + 3), nullptr, 10);
                debug_adapter->SetActiveThreadId(thread_id);
            }
            else if (auto loc = input.find("disasm ");
                    loc != std::string::npos)
            {
                auto reg_count = std::stoul(input.substr(loc + 7), nullptr, 10);
                DisasmDisplay(debug_adapter, reg_count);
            }
            else if (auto loc = input.find("bp ");
                    loc != std::string::npos)
            {
                if ( !debug_adapter->AddBreakpoint(std::stoull(input.substr(loc + 3).c_str(), nullptr, 16)) )
                    printf("failed to set bp!\n");
            }
            else if (auto loc = input.find("bpr ");
                    loc != std::string::npos)
            {
                debug_adapter->RemoveBreakpoint(
                        DebugBreakpoint(std::stoull(input.substr(loc + 4).c_str(), nullptr, 16)));
            }
            else if ( input == "bpl" )
            {
                Log::print("%i breakpoint[s] set\n", debug_adapter->GetBreakpointList().size());
                for (const auto& breakpoint : debug_adapter->GetBreakpointList())
                    Log::print("    breakpoint[%i] @ 0x%llx is %s%s\n", breakpoint.m_id, breakpoint.m_address,
                               breakpoint.m_is_active ? Log::Style(0, 255, 0).AsAnsi().c_str() : Log::Style(255, 0, 0).AsAnsi().c_str(),
                               breakpoint.m_is_active ? "active" : "not active");
            }
            else if ( input == "sr" )
            {
                Log::print<Log::Warning>("stop reason : %x\n", debug_adapter->StopReason());
            }
            else if ( input == "es" )
            {
                Log::print<Log::Info>("execution status : %x\n", debug_adapter->ExecStatus());
            }
            else if (input == "go")
            {
                debug_adapter->Go();
            }
            else if (input == "force_go")
            {
                const auto ip_name = debug_adapter->GetTargetArchitecture() == "x86" ? "eip" : "rip";
                const auto ip = debug_adapter->ReadRegister(ip_name).m_value;
                debug_adapter->WriteRegister(ip_name, ip + 1);
                debug_adapter->Go();
            }
            else if (input == "so")
            {
                debug_adapter->StepOver();
            }
            else if ( input == "sot" )
            {
                debug_adapter->StepOut();
            }
            else if ( input == "si" )
            {
                debug_adapter->StepInto();
            }
            else if (auto loc = input.find("st ");
                    loc != std::string::npos)
            {
                debug_adapter->StepTo(std::stoull(input.substr(loc + 3).c_str(), nullptr, 16));
            }
            else if (input == "detach")
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