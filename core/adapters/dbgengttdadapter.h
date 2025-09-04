/*
Copyright 2020-2025 Vector 35 Inc.

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

// Additional includes for TTD memory analysis
#ifdef WIN32
#include <dbgmodel.h>
#include <comdef.h>
#endif

namespace BinaryNinjaDebugger {
    class DbgEngTTDAdapter: public DbgEngAdapter
    {
    public:
        DbgEngTTDAdapter(BinaryView* data);

        [[nodiscard]] bool ExecuteWithArgsInternal(const std::string& path, const std::string& args,
           const std::string& workingDir, const LaunchConfigurations& configs = {}) override;
		bool WriteMemory(std::uintptr_t address, const DataBuffer& buffer) override;
		bool WriteRegister(const std::string& reg, intx::uint512 value) override;

		bool Start() override;
		void Reset() override;

        bool GoReverse() override;
        bool StepIntoReverse() override;
    	bool StepOverReverse() override;
    	bool StepReturnReverse() override;
    	
    	bool SupportFeature(DebugAdapterCapacity feature) override;
    	
		bool Quit() override;

		// TTD Memory Analysis Methods
		std::vector<TTDMemoryEvent> GetMemoryEvents(const TTDPosition& startPos, const TTDPosition& endPos, TTDMemoryAccessType accessType = TTDMemoryRead);
		std::vector<TTDMemoryEvent> GetMemoryEventsForAddress(uint64_t address, uint64_t size, TTDMemoryAccessType accessType = TTDMemoryRead);
		TTDPosition GetCurrentTTDPosition();
		bool SetTTDPosition(const TTDPosition& position);

    	void GenerateDefaultAdapterSettings(BinaryView* data);
    	Ref<Settings> GetAdapterSettings() override;

	private:
		// Helper methods for TTD memory analysis
		bool InitializeTTDMemoryAnalysis();
		void CleanupTTDMemoryAnalysis();
		bool QueryMemoryAccess(const TTDPosition& startPos, const TTDPosition& endPos, TTDMemoryAccessType accessType, std::vector<TTDMemoryEvent>& events);

#ifdef WIN32
		// TTD Data Model interfaces
		IDataModelManager* m_dataModelManager;
		IDebugHost* m_debugHost;
		bool m_ttdInitialized;
#endif
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
