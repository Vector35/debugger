#pragma once
#include "gdbadapter.h"

class LldbAdapter : public GdbAdapter {
public:
    bool Execute(const std::string& path) override;
    bool Go() override;
};

