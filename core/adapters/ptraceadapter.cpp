/*
Copyright 2020-2026 Vector 35 Inc.

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

#include "ptraceadapter.h"

namespace BinaryNinjaDebugger {

	bool PtraceAdapter::IsELFWithoutDynamicLoader(BinaryView* data) {

    }

	bool PtraceAdapter::CreateTarget(const std::string& file) {

    }

	bool PtraceAdapter::ResolveModuleAddress(const ModuleNameAndOffset& location, uint64_t& address) {

    }

	PtraceAdapter::PtraceAdapter(BinaryView* data) {

    }
    
	PtraceAdapter::~PtraceAdapter() {

    }

	bool PtraceAdapter::Execute(const std::string& path, const LaunchConfigurations& configs) {

    }

	bool PtraceAdapter::ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
		const LaunchConfigurations& configs)
	{

    }

	bool PtraceAdapter::Attach(std::uint32_t pid) {

    }

	bool PtraceAdapter::Connect(const std::string& server, std::uint32_t port) {

    }

	bool PtraceAdapter::Detach() {

    }

	bool PtraceAdapter::Quit() {

    }

	std::vector<DebugProcess> PtraceAdapter::GetProcessList() {

    }

	std::uint32_t PtraceAdapter::GetActivePID() {

    }

	std::vector<DebugThread> PtraceAdapter::GetThreadList() {

    }

	DebugThread PtraceAdapter::GetActiveThread() const {

    }

	uint32_t PtraceAdapter::GetActiveThreadId() const {

    }

	bool PtraceAdapter::SetActiveThread(const DebugThread& thread) {

    }

	bool PtraceAdapter::SetActiveThreadId(std::uint32_t tid) {

    }

	bool PtraceAdapter::SuspendThread(std::uint32_t tid) {

    }
	bool PtraceAdapter::ResumeThread(std::uint32_t tid) {

    }

	std::vector<DebugFrame> PtraceAdapter::GetFramesOfThread(uint32_t tid) {

    }

	DebugBreakpoint PtraceAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type) {

    }

	DebugBreakpoint PtraceAdapter::AddBreakpoint(
		const ModuleNameAndOffset& address, unsigned long breakpoint_type = 0)
	{

    }

	bool PtraceAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint) {

    }

	bool PtraceAdapter::RemoveBreakpoint(const ModuleNameAndOffset& address) {

    }

	std::vector<DebugBreakpoint> PtraceAdapter::GetBreakpointList() const {

    }

	// Hardware breakpoint and watchpoint support
	bool PtraceAdapter::AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size) {

    }
	bool PtraceAdapter::RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size) {

    }
	bool PtraceAdapter::AddHardwareBreakpoint(
		const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
	{

    }
	bool PtraceAdapter::RemoveHardwareBreakpoint(
		const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
	{

    }

	std::unordered_map<std::string, DebugRegister> PtraceAdapter::ReadAllRegisters() {

    }

	DebugRegister PtraceAdapter::ReadRegister(const std::string& reg) {

    }

	bool PtraceAdapter::WriteRegister(const std::string& reg, intx::uint512 value) {

    }

	DataBuffer PtraceAdapter::ReadMemory(std::uintptr_t address, std::size_t size) {

    }

	bool PtraceAdapter::WriteMemory(std::uintptr_t address, const DataBuffer& buffer) {

    }

	std::vector<DebugModule> PtraceAdapter::GetModuleList() {

    }

	std::vector<DebugMemoryRegion> PtraceAdapter::GetMemoryMap() {

    }

	std::vector<DebugSymbol> PtraceAdapter::GetSymbolsForModule(const DebugModule& module) {

    }

	std::string PtraceAdapter::GetTargetArchitecture() {

    }

	DebugStopReason PtraceAdapter::StopReason() {

    }

	uint64_t PtraceAdapter::ExitCode() {

    }

	bool PtraceAdapter::BreakInto() {

    }

	bool PtraceAdapter::Go() {

    }

	bool PtraceAdapter::StepInto() {

    }

	bool PtraceAdapter::StepOver() {

    }

	bool PtraceAdapter::StepReturn() {

    }

	std::string PtraceAdapter::InvokeBackendCommand(const std::string& command) {

    }

	uint64_t PtraceAdapter::GetInstructionOffset() {

    }

	uint64_t PtraceAdapter::GetStackPointer() {

    }

	bool PtraceAdapter::SupportFeature(DebugAdapterCapacity feature) {

    }

	void PtraceAdapter::EventListener() {

    }

	void PtraceAdapter::WriteStdin(const std::string& msg) {

    }

	void PtraceAdapter::FixActiveThread() {

    }

	Ref<Metadata> PtraceAdapter::GetProperty(const std::string& name) {

    }

	bool PtraceAdapter::SetProperty(const std::string& name, const Ref<Metadata>& value) {

    }

	bool PtraceAdapter::ConnectToDebugServer(const std::string& server, std::uint32_t port) {

    }

	bool PtraceAdapter::DisconnectDebugServer() {

    }

	void PtraceAdapter::ApplyBreakpoints() {

    }

	void PtraceAdapter::GenerateDefaultAdapterSettings(BinaryView* data) {

    }
	Ref<Settings> PtraceAdapter::GetAdapterSettings() {

    }

}  // namespace BinaryNinjaDebugger
