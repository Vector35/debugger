#include "debugadapter.h"

std::string DebugAdapter::GetPath() const
{
    return this->m_path;
}

std::uint32_t DebugAdapter::GetPid() const
{
    return this->m_pid;
}

std::uintptr_t DebugAdapter::TargetBase() const
{
    return this->m_target_base;
}
