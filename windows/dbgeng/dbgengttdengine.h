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
#include "dbgengengine.h"

// Additional includes for TTD memory analysis
#include <dbgmodel.h>
#include <comdef.h>
#include <wrl/client.h>
using namespace Microsoft::WRL;

namespace BinaryNinjaDebugger {
    class DbgEngTTDEngine: public DbgEngEngine
    {
    public:
        DbgEngTTDEngine();

        [[nodiscard]] bool ExecuteWithArgsInternal(const std::string& path, const std::string& args,
           const std::string& workingDir) override;
		bool WriteMemory(std::uintptr_t address, const std::vector<uint8_t>& buffer) override;
		bool WriteRegister(const std::string& reg, intx::uint512 value) override;

		bool Start() override;
		void Reset() override;
		bool TerminateTargetOnEngineThread() override;

        bool GoReverse();
        bool StepIntoReverse();
    	bool StepOverReverse();
    	bool StepReturnReverse();
    	
    	bool SupportFeature(DebugAdapterCapacity feature) override;
    	
		bool Quit() override;

		// TTD Memory Analysis Methods
		std::vector<TTDMemoryEvent> GetTTDMemoryAccessForAddress(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType, uint64_t maxResults);
		std::vector<TTDPositionRangeIndexedMemoryEvent> GetTTDMemoryAccessForPositionRange(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType, TTDPosition startTime, TTDPosition endTime, uint64_t maxResults);

		// TTD Position Methods
		TTDPosition GetCurrentTTDPosition();
		bool SetTTDPosition(const TTDPosition& position);

		// TTD Next/Prev Memory Access Methods
		std::pair<bool, TTDMemoryEvent> GetTTDNextMemoryAccess(uint64_t address, uint64_t size, TTDMemoryAccessType accessType);
		std::pair<bool, TTDMemoryEvent> GetTTDPrevMemoryAccess(uint64_t address, uint64_t size, TTDMemoryAccessType accessType);

		// TTD Next/Prev Register Write Methods
		std::optional<TTDRegisterWriteEvent> GetTTDNextRegisterWrite(const std::string& reg);
		std::optional<TTDRegisterWriteEvent> GetTTDPrevRegisterWrite(const std::string& reg);

    	// TTD Calls Analysis Methods
    	std::vector<TTDCallEvent> GetTTDCallsForSymbols(const std::string& symbols, uint64_t startReturnAddress, uint64_t endReturnAddress, uint64_t maxResults);

    	// TTD Events Analysis Methods
    	std::vector<TTDEvent> GetTTDEvents(TTDEventType eventType, uint64_t maxResults);
    	std::vector<TTDEvent> GetAllTTDEvents(uint64_t maxResults);

	private:
		// Helper methods for TTD memory analysis
		bool QueryMemoryAccessByAddress(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType, uint64_t maxResults, std::vector<TTDMemoryEvent>& events);
		bool QueryMemoryAccessByAddressAndPositionRange(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType, TTDPosition startTime, TTDPosition endTime, uint64_t maxResults, std::vector<TTDPositionRangeIndexedMemoryEvent>& events);
		
		// Helper methods for TTD calls analysis
		bool QueryCallsForSymbols(const std::vector<std::string>& symbols, uint64_t startReturnAddress, uint64_t endReturnAddress, uint64_t maxResults, std::vector<TTDCallEvent>& events);
		bool ParseTTDCallObjects(const std::string& expression, uint64_t maxResults, std::vector<TTDCallEvent>& events);

		// Helper methods for TTD events analysis
		bool QueryAllTTDEvents(uint64_t maxResults);
		bool ParseTTDEventObjects(const std::string& expression, uint64_t maxResults, std::vector<TTDEvent>& events);
		void ParseThreadDetails(IModelObject* eventObject, TTDEvent& event);
		void ParseModuleDetails(IModelObject* eventObject, TTDEvent& event);
		void ParseExceptionDetails(IModelObject* eventObject, TTDEvent& event);
		void ParseTTDPosition(IModelObject* positionObj, TTDPosition& position);
		
		// TTD Events cache
		std::vector<TTDEvent> m_cachedEvents;
		bool m_eventsCached;
		
		// Method to clear TTD events cache
		void ClearTTDEventsCache();

		// Data model helper methods
		std::string EvaluateDataModelExpression(const std::string& expression);
		bool ParseTTDMemoryObjects(const std::string& expression, TTDMemoryAccessType accessType, uint64_t maxResults, std::vector<TTDMemoryEvent>& events);
		bool ParseTTDPositionRangeIndexedMemoryObjects(const std::string& expression, TTDMemoryAccessType accessType, uint64_t maxResults, std::vector<TTDPositionRangeIndexedMemoryEvent>& events);
		std::pair<bool, TTDMemoryEvent> ParseSingleTTDMemoryObject(const std::string& expression, TTDMemoryAccessType accessType);
		std::optional<TTDRegisterWriteEvent> ParseSingleTTDRegisterWriteObject(const std::string& expression, const std::string& reg);

		// Data model interfaces for TTD
		IHostDataModelAccess* m_dataModelManager {nullptr};
    	IDataModelManager* m_modelMgr {nullptr};
		IDebugHost* m_debugHost {nullptr};
		IDebugHostEvaluator* m_hostEvaluator {nullptr};
    };
};
