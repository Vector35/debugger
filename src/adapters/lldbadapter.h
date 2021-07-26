#pragma once
#include "gdbadapter.h"

class LldbAdapter : public GdbAdapter {
    bool LoadRegisterInfo() override;

public:
    bool ExecuteWithArgs(const std::string& path, const std::vector<std::string>& args) override;
    bool Go() override;
    std::string GetTargetArchitecture() override;
};

