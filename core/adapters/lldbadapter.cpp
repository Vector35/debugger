#include "lldbadapter.h"
#include "SBDebugger.h"

using namespace BinaryNinjaDebugger;

LldbAdapter::LldbAdapter(BinaryView *data): DebugAdapter(data)
{
	lldb::SBDebugger::Initialize();
}


LldbAdapterType::LldbAdapterType(): DebugAdapterType("LLDB")
{

}


DebugAdapter* LldbAdapterType::Create(BinaryNinja::BinaryView *data)
{
	// TODO: someone should free this.
    return new LldbAdapter(data);
}


bool LldbAdapterType::IsValidForData(BinaryNinja::BinaryView *data)
{
//	it does not matter what the BinaryViewType is -- as long as we can connect to it, it is fine.
	return true;
}


bool LldbAdapterType::CanConnect(BinaryNinja::BinaryView *data)
{
//	We can connect to remote lldb on any host system
    return true;
}


bool LldbAdapterType::CanExecute(BinaryNinja::BinaryView *data)
{
    return true;
}


void BinaryNinjaDebugger::InitLldbAdapterType()
{
    static LldbAdapterType lldbType;
    DebugAdapterType::Register(&lldbType);
}
bool LldbAdapter::Execute(const std::string & path, const LaunchConfigurations & configs){
return false;
}bool LldbAdapter::ExecuteWithArgs(const std::string & path, const std::string & args, const LaunchConfigurations & configs){
return false;
}bool LldbAdapter::Attach(std::uint32_t pid){
return false;
}bool LldbAdapter::Connect(const std::string & server, std::uint32_t port){
return false;
}void LldbAdapter::Detach(){

}void LldbAdapter::Quit(){

}std::vector<DebugThread> LldbAdapter::GetThreadList(){
return std::vector<DebugThread>();
}DebugThread LldbAdapter::GetActiveThread() const{
return DebugThread();
}uint32_t LldbAdapter::GetActiveThreadId() const{
return 0;
}bool LldbAdapter::SetActiveThread(const DebugThread & thread){
return false;
}bool LldbAdapter::SetActiveThreadId(std::uint32_t tid){
return false;
}DebugBreakpoint LldbAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type){
return DebugBreakpoint();
}std::vector<DebugBreakpoint> LldbAdapter::AddBreakpoints(const std::vector<std::uintptr_t> & breakpoints){
return std::vector<DebugBreakpoint>();
}bool LldbAdapter::RemoveBreakpoint(const DebugBreakpoint & breakpoint){
return false;
}bool LldbAdapter::RemoveBreakpoints(const std::vector<DebugBreakpoint> & breakpoints){
return false;
}bool LldbAdapter::ClearAllBreakpoints(){
return false;
}std::vector<DebugBreakpoint> LldbAdapter::GetBreakpointList() const{
return std::vector<DebugBreakpoint>();
}std::string LldbAdapter::GetRegisterNameByIndex(std::uint32_t index) const{
return std::string();
}std::unordered_map<std::string, DebugRegister> LldbAdapter::ReadAllRegisters(){
return std::unordered_map<std::string, DebugRegister>();
}DebugRegister LldbAdapter::ReadRegister(const std::string & reg){
return DebugRegister();
}bool LldbAdapter::WriteRegister(const std::string & reg, std::uintptr_t value){
return false;
}bool LldbAdapter::WriteRegister(const DebugRegister & reg, std::uintptr_t value){
return false;
}std::vector<std::string> LldbAdapter::GetRegisterList() const{
return std::vector<std::string>();
}DataBuffer LldbAdapter::ReadMemory(std::uintptr_t address, std::size_t size){
return DataBuffer();
}bool LldbAdapter::WriteMemory(std::uintptr_t address, const DataBuffer & buffer){
return false;
}std::vector<DebugModule> LldbAdapter::GetModuleList(){
return std::vector<DebugModule>();
}std::string LldbAdapter::GetTargetArchitecture(){
return std::string();
}DebugStopReason LldbAdapter::StopReason(){
return SignalBus;
}unsigned long LldbAdapter::ExecStatus(){
return 0;
}uint64_t LldbAdapter::ExitCode(){
return 0;
}bool LldbAdapter::BreakInto(){
return false;
}DebugStopReason LldbAdapter::Go(){
return SignalBus;
}DebugStopReason LldbAdapter::StepInto(){
return SignalBus;
}DebugStopReason LldbAdapter::StepOver(){
return SignalBus;
}void LldbAdapter::Invoke(const std::string & command){

}uintptr_t LldbAdapter::GetInstructionOffset(){
return 0;
}bool LldbAdapter::SupportFeature(DebugAdapterCapacity feature){
return false;
}
