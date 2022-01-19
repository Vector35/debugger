#pragma once

#include "binaryninjaapi.h"
#include "viewframe.h"
#include "debuggerevent.h"

using namespace BinaryNinja;
class DebuggerController;

class DebugProcessView: public BinaryView
{
    std::vector<uint64_t> m_entryPoints;
    size_t m_addressSize;
    BNEndianness m_endian;
    ArchitectureRef m_arch;
    PlatformRef m_platform;

    std::map<uint64_t, DataBuffer> m_valueCache;
    std::set<uint64_t> m_errorCache;
    std::recursive_mutex m_memoryMutex;

    DebuggerController* m_controller = nullptr;
	size_t m_eventCallback;

    virtual uint64_t PerformGetEntryPoint() const override;

    virtual bool PerformIsExecutable() const override { return true; }
    virtual BNEndianness PerformGetDefaultEndianness() const override;
    virtual bool PerformIsRelocatable() const override { return true; };
    virtual size_t PerformGetAddressSize() const override;
    virtual bool PerformIsValidOffset(uint64_t addr) override { return true; }
    virtual uint64_t PerformGetLength() const override;

    virtual size_t PerformRead(void* dest, uint64_t offset, size_t len) override;
    virtual size_t PerformWrite(uint64_t offset, const void* data, size_t len) override;

public:
    DebugProcessView(BinaryView* data);
    virtual ~DebugProcessView();
    virtual bool Init() override;

    void MarkDirty();
	void eventHandler(const DebuggerEvent& event);
};


class DebugProcessViewType: public BinaryViewType
{
public:
    DebugProcessViewType();
    virtual BinaryView* Create(BinaryView* data) override;
    virtual BinaryView* Parse(BinaryView* data) override;
    virtual bool IsTypeValidForData(BinaryView* data) override { return true; }
    virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override { return nullptr; }
};


void InitDebugProcessViewType();
