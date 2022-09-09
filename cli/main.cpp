/*
Copyright 2020-2022 Vector 35 Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <iostream>
#include <thread>
#include <atomic>
#include <sys/stat.h>

#ifndef WIN32
#include <csignal>
#endif

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"
#include "debuggerapi.h"
#include "log.h"
#include "fmt/format.h"

using namespace BinaryNinja;
using namespace std;
using namespace BinaryNinjaDebuggerAPI;


std::atomic_bool shouldBreak = false;
void signalHandler(int sigNum)
{
	shouldBreak = true;
}


void RegisterDisplay(DbgRef<DebuggerController> debugger)
{
    const auto arch = debugger->GetRemoteArchitecture();
    if (!arch)
        return;

    auto all_regs = debugger->GetRegisters();

    auto reg = [debugger](std::string reg_name)
    {
        auto original_name = reg_name;
        reg_name.erase(std::remove(reg_name.begin(), reg_name.end(), ' '), reg_name.end());

        return fmt::format("{}{}\033[0m={:016X}", Log::Style( 255, 165, 0 ), original_name,
						   debugger->GetRegisterValue(reg_name));
    };

    auto reg32 = [debugger](std::string reg_name)
    {
        auto original_name = reg_name;
        reg_name.erase(std::remove(reg_name.begin(), reg_name.end(), ' '), reg_name.end());

        return fmt::format("{}{}\033[0m={:08X}", Log::Style( 255, 165, 0 ), original_name,
                           debugger->GetRegisterValue(reg_name));
    };

    auto reg16 = [debugger](std::string reg_name)
    {
        auto original_name = reg_name;
        reg_name.erase(std::remove(reg_name.begin(), reg_name.end(), ' '), reg_name.end());

        return fmt::format("{}{}\033[0m={:04X}", Log::Style( 255, 165, 0 ), original_name,
                           debugger->GetRegisterValue(reg_name));
    };

    if (arch->GetName() == "x86_64" )
    {
        const auto reg_list = fmt::format("{} {} {} {}\n{} {} {} {}\n{} {} {} {}\n{} {} {} {}\n{}\n",
                                          reg("rax"), reg("rbx"), reg("rcx"), reg("rdx"),
                                          reg("rsi"), reg("rdi"), reg("rbp"), reg("rsp"),
                                          reg(" r8"), reg(" r9"), reg("r10"), reg("r11"),
                                          reg("r12"), reg("r13"), reg("r14"), reg("r15"),
                                          reg("rip")  );
        Log::print(reg_list);

        const auto register_list = debugger->GetRegisters();

		for (const DebugRegister& r: register_list)
		{
			if (r.m_name == "rflags")
			{
				Log::print(reg("rflags"));
				Log::print("\n");
			}
			else if (r.m_name == "eflags")
			{
				Log::print(reg32("eflags"));
				Log::print("\n");
			}
		}
    }
    else if (arch->GetName() == "x86" )
    {
        const auto reg_list = fmt::format("{} {} {} {}\n{} {} {} {}\n{} {}\n",
                                          reg32("eax"), reg32("ebx"), reg32("ecx"), reg32("edx"),
                                          reg32("esi"), reg32("edi"), reg32("ebp"), reg32("esp"),
                                          reg32("eip"), reg32("eflags") );
        Log::print(reg_list);
    }
    else if (arch->GetName() == "aarch64")
	{
        const auto reg_list = fmt::format("{} {} {} {}\n{} {} {} {}\n{} {} {} {}\n{} {} {} {}\n"
										  "{} {} {} {}\n{} {} {} {}\n{} {} {} {}\n{} {} {}\n"
										  "{} {}\n",
                                          reg("x0"), reg("x1"), reg("x2"), reg("x3"),
                                          reg("x4"), reg("x5"), reg("x6"), reg("x7"),
                                          reg("x8"), reg("x9"), reg("x10"), reg("x11"),
                                          reg("x12"), reg("x13"), reg("x14"), reg("x15"),
                                          reg("x16"), reg("x17"), reg("x18"), reg("x19"),
                                          reg("x20"), reg("x21"), reg("x22"), reg("x23"),
                                          reg("x24"), reg("x25"), reg("x26"), reg("x27"),
                                          reg("x28"), reg("x29"), reg("x30"),
										  reg("pc"), reg("sp"));
        Log::print(reg_list);
	}
	else
    {
        Log::print<Log::Error>("unknown architecture\n");
    }
}


void DisasmDisplay(DbgRef<DebuggerController> debugger, const std::uint32_t count)
{
    using namespace BinaryNinja;

    std::vector<std::string> disasm_strings{};
    std::vector<std::string> llil_strings{};
    std::vector<std::string> mlil_strings{};
    std::vector<std::string> hlil_strings{};

    std::uintptr_t instruction_increment{};
    for (std::uint32_t steps{}; steps < count; steps++)
    {
        const auto instruction_offset = debugger->IP() + instruction_increment;
        if (!instruction_offset)
            return;

        const auto architecture = debugger->GetRemoteArchitecture();
        if (!architecture)
            return;

        const auto data = debugger->ReadMemory(instruction_offset, 16);
        if (data.GetLength() == 0)
            return;

		size_t size = data.GetLength();
        std::vector<InstructionTextToken> instruction_tokens{};
        if (!architecture->GetInstructionText((const uint8_t*)data.GetData(), instruction_offset, size, instruction_tokens)) {
            printf("failed to disassemble\n");
            return;
        }

        instruction_increment += size;

        auto data_buffer = DataBuffer(data.GetData(), size);
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
            if ( arch->GetName() == os + "-"s + debugger->GetRemoteArchitecture()->GetName() )
            {
                plat = arch;
                break;
            }
        }

        bv->AddFunctionForAnalysis(plat, 0);

        for ( const auto& instruction : instruction_tokens ) {
            if (instruction.type == BNInstructionTextTokenType::InstructionToken) {
                disasm_strings.emplace_back(fmt::format("[{:X}] ", instruction_offset + instruction.size));
            }
            disasm_strings.push_back(instruction.text);
        }
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

    static const auto disasm_style = Log::Style(0,255,255);
    static const auto llil_style = Log::Style(0,255,0);
    static const auto mlil_style = Log::Style(255,255,0);
    static const auto hlil_style = Log::Style(255,0,0);
    fmt::print("\033[0m[{0}disasm\033[0m] {0}\n", disasm_style);
    for ( const auto& disasm : disasm_strings )
        fmt::print("{}", disasm);

    fmt::print("\033[0m[{0}llil\033[0m] {0}\n", llil_style);
    for ( const auto& llil : llil_strings )
        fmt::print("{}", llil);

    fmt::print("\033[0m[{0}mlil\033[0m] {0}\n", mlil_style);
    for ( const auto& mlil : mlil_strings )
        fmt::print("{}", mlil);

    fmt::print("\033[0m[{0}hlil\033[0m] {0}\n", hlil_style);
    for ( const auto& hlil : hlil_strings )
        fmt::print("{}", hlil);
}


bool is_file(const char* fname)
{
	struct stat buf;
	if (stat(fname, &buf) == 0 && (buf.st_mode & S_IFREG) == S_IFREG)
		return true;

	return false;
}


void PrintStopReason(DbgRef<DebuggerController> controller, DebugStopReason reason)
{
	if (reason == ProcessExited)
	{
		Log::print<Log::Info>("Exited with code: {}\n", controller->GetExitCode());
		return;
	}
	Log::print<Log::Info>("stopped: {}\n", controller->GetDebugStopReasonString(reason));
}


int main(int argc, const char* argv[])
{
    Log::SetupAnsi();
    LogToStdout(WarningLog);

    if (argc != 2 && argc != 4)
    {
        Log::print<Log::Error>("usage: {} <debuggee_path>\n", argv[0]);
        Log::print<Log::Error>("usage: {} <debuggee_path> --attach <debuggee_pid>\n", argv[0]);
        Log::print<Log::Error>("usage: {} <debuggee_path> --connect <host:port>\n", argv[0]);
        return 0;
    }

    Log::SetupAnsi();

    SetBundledPluginDirectory(GetBundledPluginDirectory());
    InitPlugins();

	const char* fname = argv[1];
	if (!is_file(fname))
	{
		cerr << "Error: " << fname << " is not a regular file" << endl;
		exit(-1);
	}

	SetBundledPluginDirectory(GetBundledPluginDirectory());
	InitPlugins();

	Ref<BinaryData> bd = new BinaryData(new FileMetadata(argv[1]), argv[1]);
	Ref<BinaryView> bv;
	for (auto type : BinaryViewType::GetViewTypes())
	{
		if (type->IsTypeValidForData(bd) && type->GetName() != "Raw")
		{
			bv = type->Create(bd);
			break;
		}
	}

	if (!bv || bv->GetTypeName() == "Raw")
	{
		fprintf(stderr, "Input file does not appear to be an exectuable\n");
		return -1;
	}

	bv->UpdateAnalysisAndWait();

	DbgRef<DebuggerController> debugger = DebuggerController::GetController(bv);
	if (!debugger)
		LogError("fail to create a debugger for the binaryview\n");

	if (argc == 2)
	{
		debugger->SetExecutablePath(argv[1]);
		if (!debugger->Launch())
		{
			LogError("%s", fmt::format("failed to execute {}\n", argv[1]).c_str());
			return -1;
		}
	}
	// argc == 4
	else if (strcmp(argv[2], "--connect") == 0)
	{
		string hostAndPort = string(argv[3]);
		size_t pos = hostAndPort.find(':');
		if (pos == string::npos)
			return -1;
		string host = hostAndPort.substr(0, pos);
		if (host.empty())
			host = "localhost";
		string portStr = hostAndPort.substr(pos + 1);
		if (portStr.empty())
			return -1;
		int32_t port = std::stoi(portStr);
		debugger->SetRemoteHost(host);
		debugger->SetRemotePort(port);
		debugger->Connect();
	}
	else if (strcmp(argv[2], "--attach") == 0)
	{
		uint32_t pid = std::stoi(argv[3]);
		if (pid == 0)
			return -1;
		if (!debugger->Attach(pid))
			return -1;
	}

#ifdef WIN32
	std::thread([&]{
		while (true )
			if (GetAsyncKeyState(VK_F2) & 1)
				debugger->Pause();
	}).detach();
#else
	std::thread([&]{
		while (true)
		{
			if (shouldBreak)
			{
				if (debugger->IsRunning())
					debugger->Pause();
				shouldBreak = false;
			}
		}
	}).detach();

	signal(SIGINT, signalHandler);
#endif

	char input_buf[256];
	const auto red_style = Log::Style(255, 90, 90);
	const auto white_style = Log::Style(255, 255, 255);
	while ( Log::print("{}BINJA{}DBG{}> ", red_style, white_style, red_style ) && std::cin.getline(input_buf, sizeof(input_buf)) )
	{
		auto input = std::string(input_buf);
		if ( input == "help" )
		{
			const auto bar_style = Log::Style(200, 180, 190);
			const auto blue_style = Log::Style(0, 255, 255);

			constexpr auto help_string = "{}===== {}BINJA{}DBG{} {}=====\n";
			Log::print(help_string, bar_style, red_style, white_style, red_style, bar_style);

			auto print_arg = [&](const std::string& cmd, const std::string& description, const std::string& args = "")
			{
				Log::print("{}| {}{}{}, {}{}", bar_style, blue_style, cmd, white_style, white_style, description);
				if ( !args.empty() )
					Log::print(" -> takes {}{}", red_style, args);
				Log::print("\n");
			};

			print_arg("break", "breaks in");
			print_arg(".", "invokes debugger backend", "command");
			print_arg(">", "write to stdin", "input");
			print_arg("lt", "list all threads");
			print_arg("lm", "list all modules");
			print_arg("lbp", "list all breakpoints");
			print_arg("reg", "display registers");
			print_arg("disasm", "disassemble & lift instructions", "instruction count");
			print_arg("sr", "display stop reason");
			print_arg("es", "display execution status");
			print_arg("bp", "add a breakpoint", "address (hex)");
			print_arg("bpr", "remove a breakpoint", "address (hex)");
			print_arg("c", "go");
			print_arg("r", "launch");
			print_arg("force_go", "increment instruction pointer and go");
			print_arg("ni", "step over");
			print_arg("finish", "step out");
			print_arg("si", "step into");
			print_arg("st", "step to", "address (hex)");
			print_arg("ts", "set active thread", "thread id");
			print_arg("detach", "detach debugger");
			print_arg("kill", "kill the target");
			print_arg("end", "quit this cli debugger");
		}
		if ( input[0] == '.' )
		{
			const std::string result = debugger->InvokeBackendCommand(input.substr(1));
			Log::print<Log::Info>("{}", result.c_str());
		}
		if ( input[0] == '>' )
		{
			debugger->WriteStdin(input.substr(1));
		}
		else if ( input == "testwrite" )
		{
			debugger->SetRegisterValue("rip",  0);
		}
		else if ( input == "lm" )
		{
			Log::print( "[modules]\n" );
			for ( const auto& module : debugger->GetModules() )
				Log::print<Log::Info>( "[{}, {}] {} @ 0x{:X} with size 0x{:X}\n",
									   module.m_name.c_str(), module.m_short_name.c_str(),
									   module.m_loaded ? "is loaded" : "was unloaded", module.m_address, module.m_size );
		}
		else if ( input == "lt" )
		{
			Log::print( "[threads]\n" );
			for ( const auto& thread : debugger->GetThreads() )
				Log::print<Log::Info>( "tid {}, rip=0x{:x}\n", thread.m_tid, thread.m_rip );
		}
		else if (input == "reg")
		{
			RegisterDisplay(debugger);
		}
		else if (auto loc = input.find("ts ");
				loc != std::string::npos)
		{
			auto thread_id = std::stoul(input.substr(loc + 3), nullptr, 10);
			debugger->SetActiveThread(thread_id);
		}
		else if (input == "disasm")
		{
			DisasmDisplay(debugger, 10);
		}
		else if (auto loc = input.find("disasm ");
				loc != std::string::npos)
		{
			auto count = std::stoul(input.substr(loc + 7), nullptr, 10);
			if (count == 0)
				count = 10;
			DisasmDisplay(debugger, count);
		}
		else if (auto loc = input.find("bp ");
				loc != std::string::npos)
		{
			debugger->AddBreakpoint(std::stoull(input.substr(loc + 3).c_str(), nullptr, 16));
		}
		else if (auto loc = input.find("bpr ");
				loc != std::string::npos)
		{
			debugger->DeleteBreakpoint(std::stoull(input.substr(loc + 4).c_str(), nullptr, 16));
		}
		else if ( input == "lbp" )
		{
			Log::print("{} breakpoint[s] set\n", debugger->GetBreakpoints().size());
			size_t i = 0;
			for (const auto& breakpoint : debugger->GetBreakpoints())
			{
				Log::print("    breakpoint[{}] @ 0x{:X} is {}{}\n", i, breakpoint.address,
						   breakpoint.enabled ? Log::Style(0, 255, 0)
												  : Log::Style(255, 0, 0),
						   breakpoint.enabled ? "active" : "inactive");
				i++;
			}
		}
		else if ( input == "sr" )
		{
			auto reason = debugger->StopReason();
			Log::print<Log::Warning>("stop reason : {}\n", DebuggerController::GetDebugStopReasonString(reason));
		}
		else if ( input == "es" )
		{
			Log::print<Log::Info>("execution status : {}\n", debugger->GetTargetStatus());
		}
		else if (input == "c")
		{
			DebugStopReason reason = debugger->GoAndWait();
			PrintStopReason(debugger, reason);
		}
		else if (input == "r")
		{
			[[maybe_unused]] bool result = debugger->Launch();
		}
		else if (input == "force_go")
		{
			string ip_name = "";
			const string archName = debugger->GetRemoteArchitecture()->GetName();
			if (archName == "x86")
				ip_name = "eip";
			else if (archName == "x64")
				ip_name = "rip";
			else
				ip_name = "pc";

			const auto ip = debugger->IP();
			debugger->SetRegisterValue(ip_name, ip + 1);
			DebugStopReason reason = debugger->GoAndWait();
			PrintStopReason(debugger, reason);
		}
		else if (input == "ni")
		{
			DebugStopReason reason = debugger->StepOverAndWait();
			PrintStopReason(debugger, reason);
		}
		else if ( input == "sot" )
		{
			DebugStopReason reason = debugger->StepReturnAndWait();
			PrintStopReason(debugger, reason);
		}
		else if ( input == "si" )
		{
			DebugStopReason reason = debugger->StepIntoAndWait();
			PrintStopReason(debugger, reason);
		}
		else if ( input == "finish" )
		{
			DebugStopReason reason = debugger->StepReturnAndWait();
			PrintStopReason(debugger, reason);
		}
		else if (auto loc = input.find("st ");
				loc != std::string::npos)
		{
			DebugStopReason reason = debugger->RunToAndWait(std::stoull(input.substr(loc + 3).c_str(), nullptr, 16));
			PrintStopReason(debugger, reason);
		}
		else if (input == "detach")
		{
			debugger->Detach();
		}
		else if (input == "kill")
		{
			debugger->Quit();
		}
		else if (input == "break")
		{
			debugger->Pause();
		}
		else if (input == "end")
		{
			break;
		}
		else if (!input.empty())
		{
			Log::print<Log::Info>("invalid command\n");
		}
	}

	BNShutdown();
}