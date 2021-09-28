#pragma once

#include "binaryninjaapi.h"
#include "viewframe.h"

using namespace BinaryNinja;

// The debug memory BinaryView layout is in a few pieces:
// - DebugProcessView represents the entire debugged process, containing segments for mapped memory
// - DebugMemoryView represents the raw memory of the process (eg like a raw BinaryView)

class DebugMemoryView;
class DebugProcessView: public BinaryView
{
    std::vector<uint64_t> m_entryPoints;
    size_t m_addressSize;
    BNEndianness m_endian;

    virtual uint64_t PerformGetEntryPoint() const override;

    virtual bool PerformIsExecutable() const override { return true; }
    virtual BNEndianness PerformGetDefaultEndianness() const override;
    virtual bool PerformIsRelocatable() const override { return true; };
    virtual size_t PerformGetAddressSize() const override;
public:
    DebugProcessView(BinaryView* data);
    virtual ~DebugProcessView();

    virtual bool Init() override;

private:
    DebugMemoryView* m_memory;
    BinaryView* m_localView;
    ArchitectureRef m_arch;
    PlatformRef m_platform;

    std::map<std::string, uint64_t> m_moduleBases;

//    virtual bool PerformIsExecutable() const override { return true; }
    virtual bool PerformIsValidOffset(uint64_t addr) override { return true; }

//    virtual size_t PerformGetAddressSize() const override;
    virtual uint64_t PerformGetLength() const override;

public:
//    DebugProcessView(BinaryView* parent);
    void MarkDirty();
    void ClearModuleBases();
    uint64_t GetRemoteBase(BinaryViewRef relativeView = nullptr);
    bool IsCodeASLR(BinaryViewRef relativeView = nullptr);
    uint64_t LocalAddressToRemote(uint64_t localAddr, BinaryViewRef relativeView = nullptr);
    uint64_t RemoteAddressToLocal(uint64_t remoteAddr, BinaryViewRef relativeView = nullptr);
    bool IsLocalAddress(uint64_t remoteAddr, BinaryViewRef relativeView = nullptr);
};


class DebugProcessViewType: public BinaryViewType
{
public:
    DebugProcessViewType();
    virtual BinaryView* Create(BinaryView* data) override;
    virtual BinaryView* Parse(BinaryView* data) override;
    virtual bool IsTypeValidForData(BinaryView* data) override { return false; }
    virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override { return nullptr; }
};


void InitDebugProcessViewType();


class DebugMemoryView: public BinaryView
{
private:
    ArchitectureRef m_arch;
    PlatformRef m_platform;
    std::map<uint64_t, std::vector<uint8_t>> m_valueCache;
    std::set<uint64_t> m_errorCache;

    std::mutex m_memoryMutex;

    virtual bool PerformIsExecutable() const override { return true; }
    virtual bool PerformIsValidOffset(uint64_t addr) override { return true; }
    virtual size_t PerformRead(void* dest, uint64_t offset, size_t len) override;
    virtual size_t PerformWrite(uint64_t offset, const void* data, size_t len) override;

public:
    DebugMemoryView(BinaryView* parent);
    virtual size_t PerformGetAddressSize() const override;
    virtual uint64_t PerformGetLength() const override;
    void MarkDirty();
};


class DebugMemoryViewType: public BinaryViewType
{
public:
    DebugMemoryViewType();
    virtual BinaryView* Create(BinaryView* data) override;
    virtual BinaryView* Parse(BinaryView* data) override;
    virtual bool IsTypeValidForData(BinaryView* data) override { return false; }
    virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override { return nullptr; }
};

void InitDebugMemoryViewType();
