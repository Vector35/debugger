/*
Copyright 2020-2023 Vector 35 Inc.

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

#pragma once
#include "dbgengadapter.h"

namespace BinaryNinjaDebugger {
    class DbgEngTTDAdapter: public DbgEngAdapter
    {
    public:
        DbgEngTTDAdapter(BinaryView* data);

        [[nodiscard]] bool ExecuteWithArgsInternal(const std::string& path, const std::string& args,
           const std::string& workingDir, const LaunchConfigurations& configs = {}) override;
		bool WriteMemory(uint64_t address, const void* buffer, size_t size) override;
		bool WriteRegister(const std::string& reg, uint64_t value) override;

		bool Start() override;
		void Reset() override;

		bool Quit() override;

		std::string GetDbgEngPath(const std::string& arch) override;
    };

    class DbgEngTTDAdapterType : public DebugAdapterType
    {
    public:
        DbgEngTTDAdapterType();
        virtual DebugAdapter* Create(BinaryNinja::BinaryView* data);
        virtual bool IsValidForData(BinaryNinja::BinaryView* data);
        virtual bool CanExecute(BinaryNinja::BinaryView* data);
        virtual bool CanConnect(BinaryNinja::BinaryView* data);
    };

    void InitDbgEngTTDAdapterType();
};
