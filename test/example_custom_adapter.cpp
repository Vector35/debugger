/*
Copyright 2020-2025 Vector 35 Inc.

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

// Example implementation of a custom debug adapter using the C++ API

#include "../api/debuggerapi.h"
#include <iostream>

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;

class ExampleDebugAdapter : public CustomDebugAdapter
{
public:
	ExampleDebugAdapter() : CustomDebugAdapter() {}

	// Implement required abstract methods
	bool Execute(const std::string& path) override {
		std::cout << "Execute: " << path << std::endl;
		return false; // Not implemented
	}

	bool ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir) override {
		std::cout << "ExecuteWithArgs: " << path << " " << args << " in " << workingDir << std::endl;
		return false; // Not implemented
	}

	bool Attach(uint32_t pid) override {
		std::cout << "Attach to PID: " << pid << std::endl;
		return false; // Not implemented
	}

	bool Connect(const std::string& server, uint32_t port) override {
		std::cout << "Connect to: " << server << ":" << port << std::endl;
		return false; // Not implemented
	}

	bool ConnectToDebugServer(const std::string& server, uint32_t port) override {
		std::cout << "ConnectToDebugServer: " << server << ":" << port << std::endl;
		return false; // Not implemented
	}

	bool Detach() override {
		std::cout << "Detach" << std::endl;
		return false; // Not implemented
	}

	bool Quit() override {
		std::cout << "Quit" << std::endl;
		return false; // Not implemented
	}

	// Stub implementations for all other required methods
	std::vector<DebugProcess> GetProcessList() override { return {}; }
	std::vector<DebugThread> GetThreadList() override { return {}; }
	DebugThread GetActiveThread() override { return DebugThread(); }
	uint32_t GetActiveThreadId() override { return 0; }
	bool SetActiveThread(const DebugThread& thread) override { return false; }
	bool SetActiveThreadId(uint32_t tid) override { return false; }
	bool SuspendThread(uint32_t tid) override { return false; }
	bool ResumeThread(uint32_t tid) override { return false; }
	DebugBreakpoint AddBreakpoint(uint64_t address) override { return DebugBreakpoint(); }
	DebugBreakpoint AddBreakpointRelative(const std::string& module, uint64_t offset) override { return DebugBreakpoint(); }
	bool RemoveBreakpoint(uint64_t address) override { return false; }
	bool RemoveBreakpointRelative(const std::string& module, uint64_t offset) override { return false; }
	std::vector<DebugBreakpoint> GetBreakpointList() override { return {}; }
	std::unordered_map<std::string, DebugRegister> ReadAllRegisters() override { return {}; }
	DebugRegister ReadRegister(const std::string& reg) override { return DebugRegister(); }
	bool WriteRegister(const std::string& reg, const std::vector<uint8_t>& value) override { return false; }
	std::vector<uint8_t> ReadMemory(uint64_t address, size_t size) override { return {}; }
	bool WriteMemory(uint64_t address, const std::vector<uint8_t>& buffer) override { return false; }
	std::vector<DebugModule> GetModuleList() override { return {}; }
	std::string GetTargetArchitecture() override { return "x86_64"; }
	DebugStopReason StopReason() override { return static_cast<DebugStopReason>(0); }
	uint64_t ExitCode() override { return 0; }
	bool BreakInto() override { return false; }
	bool Go() override { return false; }
	bool GoReverse() override { return false; }
	bool StepInto() override { return false; }
	bool StepIntoReverse() override { return false; }
	bool StepOver() override { return false; }
	bool StepOverReverse() override { return false; }
	bool StepReturn() override { return false; }
	bool StepReturnReverse() override { return false; }
	std::string InvokeBackendCommand(const std::string& command) override { return ""; }
	uint64_t GetInstructionOffset() override { return 0; }
	uint64_t GetStackPointer() override { return 0; }
	bool SupportFeature(uint32_t feature) override { return false; }
};

class ExampleDebugAdapterType : public CustomDebugAdapterType
{
public:
	ExampleDebugAdapterType() : CustomDebugAdapterType("ExampleAdapter") {}

	std::unique_ptr<CustomDebugAdapter> Create(Ref<BinaryView> data) override {
		return std::make_unique<ExampleDebugAdapter>();
	}

	bool IsValidForData(Ref<BinaryView> data) override {
		return true; // Accept any binary view for this example
	}

	bool CanExecute(Ref<BinaryView> data) override {
		return false; // This adapter cannot execute binaries
	}

	bool CanConnect(Ref<BinaryView> data) override {
		return true; // This adapter can connect to remote targets
	}
};

// Function to register the example adapter type
void RegisterExampleDebugAdapter()
{
	static ExampleDebugAdapterType exampleType;
	exampleType.Register();
}