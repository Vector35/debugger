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

// Additional includes for TTD analysis
#include <dbgmodel.h>
#include <comdef.h>
#include <wrl/client.h>
using namespace Microsoft::WRL;

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

		// TTD Call Analysis Methods - Override base class methods
		std::vector<TTDCallEvent> GetTTDCalls(const std::vector<std::string>& symbols) override;
		std::vector<TTDCallEvent> GetTTDCallsWithAddressFilter(const std::vector<std::string>& symbols, uint64_t minReturnAddress, uint64_t maxReturnAddress) override;
		TTDPosition GetCurrentTTDPosition() override;
		bool SetTTDPosition(const TTDPosition& position) override;

	private:
		// Helper methods for parsing TTD output
		std::vector<TTDCallEvent> ParseTTDCallsOutput(const std::string& output);
		TTDPosition ParseTTDPosition(const std::string& output);
		void ParseTTDPositionFromString(const std::string& posStr, TTDPosition& position);
		
		// Data model helper methods
		std::string EvaluateDataModelExpression(const std::string& expression);
		bool ParseTTDCallsObjects(const std::string& expression, std::vector<TTDCallEvent>& events);

		// Data model interfaces for TTD
		IHostDataModelAccess* m_dataModelManager;
    	IDataModelManager* m_modelMgr;
		IDebugHost* m_debugHost;
		IDebugHostEvaluator* m_hostEvaluator;

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
