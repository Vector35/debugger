#pragma once
#include "gdbadapter.h"

class LldbAdapter : public GdbAdapter {
    bool LoadRegisterInfo() override;
    DebugStopReason SignalToStopReason(std::uint64_t signal) override;

public:
    bool ExecuteWithArgs(const std::string& path, const std::vector<std::string>& args) override;
    bool Go() override;
    std::string GetTargetArchitecture() override;
};

