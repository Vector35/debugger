#pragma once
#include "gdbadapter.h"

class LldbAdapter : public GdbAdapter {
public:
    bool Execute(const std::string& path) override;
    bool Connect(const std::string& server, std::uint32_t port) override;
};

