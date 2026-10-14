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

#pragma once
#include "dbgengadapter.h"
#include "dbgengttdengine.h"

namespace BinaryNinjaDebugger {
    class DbgEngTTDAdapter: public DbgEngAdapter
    {
		DbgEngTTDEngine& TTD() { return static_cast<DbgEngTTDEngine&>(*m_engine); }

    public:
        DbgEngTTDAdapter(BinaryView* data);

		[[nodiscard]] bool ExecuteWithArgs(const std::string& path, const std::string& args,
			const std::string& workingDir, const LaunchConfigurations& configs = {}) override;

        bool GoReverse() override;
        bool StepIntoReverse() override;
    	bool StepOverReverse() override;
    	bool StepReturnReverse() override;

		// TTD Memory Analysis Methods
		std::vector<TTDMemoryEvent> GetTTDMemoryAccessForAddress(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType = TTDMemoryRead) override;
		std::vector<TTDPositionRangeIndexedMemoryEvent> GetTTDMemoryAccessForPositionRange(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType, TTDPosition startTime, TTDPosition endTime) override;

		// TTD Position Methods
		TTDPosition GetCurrentTTDPosition() override;
		bool SetTTDPosition(const TTDPosition& position) override;

		// TTD Next/Prev Memory Access Methods
		std::pair<bool, TTDMemoryEvent> GetTTDNextMemoryAccess(uint64_t address, uint64_t size, TTDMemoryAccessType accessType) override;
		std::pair<bool, TTDMemoryEvent> GetTTDPrevMemoryAccess(uint64_t address, uint64_t size, TTDMemoryAccessType accessType) override;

		// TTD Next/Prev Register Write Methods
		std::optional<TTDRegisterWriteEvent> GetTTDNextRegisterWrite(const std::string& reg) override;
		std::optional<TTDRegisterWriteEvent> GetTTDPrevRegisterWrite(const std::string& reg) override;

    	// TTD Calls Analysis Methods
    	std::vector<TTDCallEvent> GetTTDCallsForSymbols(const std::string& symbols, uint64_t startReturnAddress = 0, uint64_t endReturnAddress = 0) override;

    	// TTD Events Analysis Methods
    	std::vector<TTDEvent> GetTTDEvents(TTDEventType eventType) override;
    	std::vector<TTDEvent> GetAllTTDEvents() override;

    	void GenerateDefaultAdapterSettings(BinaryView* data);
    	Ref<Settings> GetAdapterSettings() override;
    };

    class DbgEngTTDAdapterType : public DebugAdapterType
    {
    	static Ref<Settings> RegisterAdapterSettings();

    public:
        DbgEngTTDAdapterType();
        virtual DebugAdapter* Create(BinaryNinja::BinaryView* data);
        virtual bool IsValidForData(BinaryNinja::BinaryView* data);
        virtual bool CanExecute(BinaryNinja::BinaryView* data);
        virtual bool CanConnect(BinaryNinja::BinaryView* data);
    	static Ref<Settings> GetAdapterSettings();
    };

    void InitDbgEngTTDAdapterType();
};
