#include "debuggerstate.h"

// static GetMetadataWithDefault(const std::string key, )
// {

// }

DebuggerState::DebuggerState(BinaryViewRef data): m_data(data)
{

}


void DebuggerState::run()
{
    BinaryNinja::LogWarn("run() requested");
}


void DebuggerState::restart()
{
    BinaryNinja::LogWarn("restart() requested");
}


void DebuggerState::quit()
{
    BinaryNinja::LogWarn("quit() requested");
}


void DebuggerState::attach()
{
    BinaryNinja::LogWarn("attach() requested");
}


void DebuggerState::detach()
{
    BinaryNinja::LogWarn("detach() requested");
}


void DebuggerState::pause()
{
    BinaryNinja::LogWarn("pause() requested");
}


void DebuggerState::resume()
{
    BinaryNinja::LogWarn("resume() requested");
}


void DebuggerState::stepIntoAsm()
{
    BinaryNinja::LogWarn("stepIntoAsm() requested");
}


void DebuggerState::stepIntoIL()
{
    BinaryNinja::LogWarn("stepIntoIL() requested");
}


void DebuggerState::stepOverAsm()
{
    BinaryNinja::LogWarn("stepOverAsm() requested");
}


void DebuggerState::stepOverIL()
{
    BinaryNinja::LogWarn("stepOverIL() requested");
}


void DebuggerState::stepReturn()
{
    BinaryNinja::LogWarn("stepReturn() requested");
}


bool DebuggerState::canExec()
{
    // TODO: query the underlying DebugAdapter for the info
    return true;
}


bool DebuggerState::canConnect()
{
    // TODO: query the underlying DebugAdapter for the info
    return true;
}
