#include "processview.h"
#include "debuggerstate.h"

using namespace BinaryNinja;

static DebugProcessViewType* g_debugProcessViewType = nullptr;


DebugProcessView::DebugProcessView(BinaryView* parent):
    BinaryView("Debugged Process", parent->GetFile(), parent)
{
    m_localView = parent;
    m_arch = parent->GetDefaultArchitecture();
    m_platform = parent->GetDefaultPlatform();

    // TODO: Read segments from debugger
    uint64_t length = PerformGetLength();
    AddAutoSegment(0, length, 0, length, SegmentReadable | SegmentWritable | SegmentExecutable);
    AddAutoSection("Memory", 0, length);
}


DebugProcessView::~DebugProcessView()
{
}


bool DebugProcessView::Init()
{
    return true;

    Ref<Settings> settings = GetLoadSettings(GetTypeName());
//    if (!settings || settings->IsEmpty())
//    {
//        AddAutoSegment(0, GetParentView()->GetLength(), 0, GetParentView()->GetLength(), SegmentReadable | SegmentExecutable);
//        return true;
//    }

    std::string archName = settings->Get<std::string>("loader.architecture", this);
    Architecture* arch = Architecture::GetByName(archName);
    if (!arch)
    {
        LogError("Mapped view type could not be created! No architecture selected.");
        return false;
    }

    std::string platformName = settings->Get<std::string>("loader.platform", this);
    Ref<Platform> platform = Platform::GetByName(platformName);
    if (!platform)
        platform = arch->GetStandalonePlatform();
    SetDefaultPlatform(platform);
    SetDefaultArchitecture(platform->GetArchitecture());
    m_addressSize = arch->GetAddressSize();
    m_endian = arch->GetEndianness();

    uint64_t imageBase = settings->Get<uint64_t>("loader.imageBase", this);

//    if (settings->Contains("loader.segments"))
//    {
//        // create segments
//        std::string json = settings->Get<std::string>("loader.segments", this);
//        std::string errors;
//        Json::Value value;
//        const char* pStr = json.c_str();
//        std::unique_ptr<Json::CharReader> reader(Json::CharReaderBuilder().newCharReader());
//        if (json.size())
//        {
//            try
//            {
//                if (!reader->parse(pStr, pStr + json.size(), &value, &errors))
//                {
//                    LogError("Mapped view could not be created! Json segments parse error.");
//                    return false;
//                }
//            }
//            catch (std::exception& e)
//            {
//                LogError("Mapped view could not be created! Json segments parse exception: %s", e.what());
//                return false;
//            }
//        }
//
//        if (value.isArray())
//        {
//            SerDesContext sdc;
//            sdc.setArch(arch);
//            sdc.SetAddressTransforms([imageBase](uint64_t val) { return val - imageBase; }, [imageBase](uint64_t val) { return val + imageBase; });
//            for (const auto& i : value)
//            {
//                Ref<Segment> s = Segment::Deserialize(sdc, i);
//                if (!s)
//                {
//                    LogError("Mapped view failed to deserialize segment!");
//                    continue;
//                }
//                AddAutoSegment(s->GetStart(), s->GetLength(), s->GetDataOffset(), s->GetDataLength(), s->GetFlags());
//            }
//        }
//        else
//            LogError("Mapped view failed to deserialize segments!");
//    }
//
//    if (settings->Contains("loader.sections"))
//    {
//        // create sections
//        std::string json = settings->Get<std::string>("loader.sections", this);
//        std::string errors;
//        Json::Value value;
//        const char* pStr = json.c_str();
//        std::unique_ptr<Json::CharReader> reader(Json::CharReaderBuilder().newCharReader());
//        if (json.size())
//        {
//            try
//            {
//                if (!reader->parse(pStr, pStr + json.size(), &value, &errors))
//                {
//                    LogError("Mapped view could not be created! Json sections parse error.");
//                    return false;
//                }
//            }
//            catch (std::exception& e)
//            {
//                LogError("Mapped view could not be created! Json sections parse exception: %s", e.what());
//                return false;
//            }
//        }
//
//        if (value.isArray())
//        {
//            SerDesContext sdc;
//            sdc.setArch(arch);
//            sdc.SetAddressTransforms([imageBase](uint64_t val) { return val - imageBase; }, [imageBase](uint64_t val) { return val + imageBase; });
//            for (const auto& i : value)
//            {
//                Ref<Section> s = Section::Deserialize(sdc, i);
//                if (!s)
//                {
//                    LogError("Mapped view failed to deserialize segment!");
//                    continue;
//                }
//                AddAutoSection(s->GetName(), s->GetStart(), s->GetLength(), s->GetSemantics(), s->GetType(),
//                               s->GetAlign(), s->GetEntrySize(), s->GetLinkedSection(), s->GetInfoSection(), s->GetInfoData());
//            }
//        }
//        else
//            LogError("Mapped view failed to deserialize sections!");
//    }

    auto jsonValue = settings->GetJson("loader.entryPointOffset", this);
    if (jsonValue != "null")
    {
        uint64_t entryPoint = imageBase + settings->Get<uint64_t>("loader.entryPointOffset", this);
        m_entryPoints.push_back(entryPoint);
        AddEntryPointForAnalysis(platform, entryPoint);
        DefineAutoSymbol(new Symbol(FunctionSymbol, "_start", entryPoint));
    }

    return true;
}


uint64_t DebugProcessView::PerformGetEntryPoint() const
{
    if (m_entryPoints.size() == 0)
        return 0;

    return m_entryPoints[0];
}


BNEndianness DebugProcessView::PerformGetDefaultEndianness() const
{
    return m_endian;
}


size_t DebugProcessView::PerformGetAddressSize() const
{
    return m_addressSize;
}

//
//size_t DebugProcessView::PerformGetAddressSize() const
//{
//    return m_memory->PerformGetAddressSize();
//}
//
//
uint64_t DebugProcessView::PerformGetLength() const
{
    size_t addressSize = PerformGetAddressSize();
    const size_t bitsPerByte = 8;
    size_t bits = addressSize * bitsPerByte;
    if (bits >= 64)
        return UINT64_MAX;

    return (1UL << bits) - 1;
}


void DebugProcessView::ClearModuleBases()
{
    m_moduleBases.clear();
}


/*
Get the base address of the binary in the debugged process
*/
uint64_t DebugProcessView::GetRemoteBase(BinaryViewRef relativeView)
{
    if (!relativeView)
        relativeView = m_localView;

    auto file = relativeView->GetFile();
    if (!file)
        return 0;
    
    std::string moduleName = file->GetOriginalFilename();
    auto iter = m_moduleBases.find(moduleName);
    if (iter == m_moduleBases.end())
    {
        DebuggerState* state = DebuggerState::GetState(relativeView);
        DebuggerModules* modulesCache = state->GetModules();
        if (!modulesCache)
            // TODO: should return false, and return the address by reference
            return 0;
        uint64_t address = modulesCache->GetModuleBase(moduleName);
        m_moduleBases[moduleName] = address;
        return address;
    }
    else
    {
        return iter->second;
    }
}


/*
Determine if the debugged process is using ASLR for its code segment
(eg in a PIE binary)
*/
bool DebugProcessView::IsCodeASLR(BinaryViewRef relativeView)
{
    if (!relativeView)
        relativeView = m_localView;

    return GetRemoteBase(relativeView) != relativeView->GetStart();
}

/*
Given a local address (relative to the analysis binaryview),
find its remote address (relative to the debugged process) after ASLR
If the address is not within our view, it will be unchanged
*/
uint64_t DebugProcessView::LocalAddressToRemote(uint64_t localAddr, BinaryViewRef relativeView)
{
    if (!relativeView)
        relativeView = m_localView;

    uint64_t localBase = relativeView->GetStart();
    uint64_t remoteBase = GetRemoteBase(relativeView);
    if ((localAddr < localBase) || (localAddr >= localBase + relativeView->GetLength()))
        // Not within our local binary, return original
        return localAddr;

    return localAddr - localBase + remoteBase;
}


/*
Given a remote address (relative to the debugged process) after ASLR,
find its local address (relative to the analysis binaryview)
If the address is not within our view, it will be unchanged
*/
uint64_t DebugProcessView::RemoteAddressToLocal(uint64_t remoteAddr, BinaryViewRef relativeView)
{
    if (!relativeView)
        relativeView = m_localView;

    // TODO: Make sure the addr is within the loaded segments for our binary
	// Else return the original
    uint64_t localBase = relativeView->GetStart();
    uint64_t remoteBase = GetRemoteBase(relativeView);
    uint64_t localAddr = remoteAddr - remoteBase + localBase;
    if ((localAddr < localBase) || (localAddr >= localBase + relativeView->GetLength()))
        // Not within our local binary, return original
        return remoteAddr;

    return localAddr;
}

/*
Determine if a remote address is within the loaded BinaryView
*/
bool DebugProcessView::IsLocalAddress(uint64_t remoteAddr, BinaryViewRef relativeView)
{
    if (!relativeView)
        relativeView = m_localView;

    uint64_t localBase = relativeView->GetStart();
    uint64_t remoteBase = GetRemoteBase(relativeView);
    uint64_t localAddr = remoteAddr - remoteBase + localBase;
    return (localAddr >= localBase) && (localAddr < localBase + relativeView->GetLength());
}


DebugProcessViewType::DebugProcessViewType():
    BinaryViewType("Debugged Process", "Debugged Process")
{
}


BinaryView* DebugProcessViewType::Create(BinaryView* data)
{
	try
	{
		return new DebugProcessView(data);
	}
	catch (std::exception& e)
	{
		LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


BinaryView* DebugProcessViewType::Parse(BinaryView* data)
{
	try
	{
		return new DebugProcessView(data);
	}
	catch (std::exception& e)
	{
		LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


void InitDebugProcessViewType()
{
    static DebugProcessViewType type;
    BinaryViewType::Register(&type);
	g_debugProcessViewType = &type;
}


//DebugMemoryViewType::DebugMemoryViewType():
//    BinaryViewType("Debugged Process Memory", "Debugged Process Memory")
//{
//}
//
//
//BinaryView* DebugMemoryViewType::Create(BinaryView* data)
//{
//	try
//	{
//		return new DebugMemoryView(data);
//	}
//	catch (std::exception& e)
//	{
//		LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
//		return nullptr;
//	}
//}
//
//
//BinaryView* DebugMemoryViewType::Parse(BinaryView* data)
//{
//	try
//	{
//		return new DebugMemoryView(data);
//	}
//	catch (std::exception& e)
//	{
//		LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
//		return nullptr;
//	}
//}


//void InitDebugMemoryViewType()
//{
//    static DebugMemoryViewType type;
//    BinaryViewType::Register(&type);
//	g_debugMemoryViewType = &type;
//}


//DebugMemoryView::DebugMemoryView(BinaryView* parent):
//    BinaryView("Debugged Process Memory", parent->GetFile(), parent)
//{
//    m_arch = parent->GetDefaultArchitecture();
//    m_platform = parent->GetDefaultPlatform();
//    m_valueCache.clear();
//    m_errorCache.clear();
//}


//size_t DebugProcessView::PerformGetAddressSize() const
//{
//    Ref<BinaryView> parentView = GetParentView();
//    if (!parentView)
//        return 8;
//
//    Ref<Architecture> parentArch = parentView->GetDefaultArchitecture();
//    if (!parentArch)
//        return 8;
//
//    return parentArch->GetAddressSize();
//}


size_t DebugProcessView::PerformRead(void* dest, uint64_t offset, size_t len)
{
//    LogWarn("DebugProcessView::PerformRead, 0x%lx", offset);
    std::unique_lock<std::mutex> memoryLock(m_memoryMutex);

    Ref<BinaryView> parentView = GetParentView();
    if (!parentView)
        return 0;

    DebuggerState* state = DebuggerState::GetState(parentView);
    if ((!state) || (!state->IsConnected()))
        return 0;

    DebugAdapter* adapter = state->GetAdapter();
    if (!adapter)
        return 0;

    std::vector<uint8_t> result;
    std::vector<uint8_t> buffer;

    // ProcessView implements read caching in a manner inspired by CPU cache:
    // Reads are aligned on 256-byte boundaries and 256 bytes long

    // Cache read start: round down addr to nearest 256 byte boundary
    size_t cacheStart = offset & (~0xffLL);
    // Cache read end: round up addr+length to nearest 256 byte boundary
    size_t cacheEnd = (offset + len + 0xFF) & (~0xffLL);
    // List of 256-byte block addresses to read into the cache to fully cover this region
    for (uint64_t block = cacheStart; block < cacheEnd; block += 0x100)
    {
        // If any block cannot be read, then return false
        if (m_errorCache.find(block) != m_errorCache.end())
        {
            return 0;
        }

        auto iter = m_valueCache.find(block);
        if (iter == m_valueCache.end())
        {
            buffer.clear();
            buffer.resize(0x100);
            // The ReadMemory() function should return the number of bytes read
            bool ok = adapter->ReadMemory(block, buffer.data(), 0x100);
            if (ok)
            {
                // Treating ok as 0x100 bytes have been read
                m_valueCache[block] = buffer;
            }
            else
            {
                m_errorCache.insert(block);
                return 0;
            }
        }

        std::vector<uint8_t> cached = m_valueCache[block];
        if (offset + len < block + cached.size())
        {
            // Last block
            cached = std::vector<uint8_t>(cached.begin(), cached.begin() + (offset + len - block));
        }
        if (offset > block)
        {
            // First block
            cached = std::vector<uint8_t>(cached.begin() + offset - block, cached.end());
        }
        result.insert(result.end(), cached.begin(), cached.end());
    }

    if (result.size() == len)
    {
        memcpy(dest, result.data(), result.size());
        return len;
    }
    return 0;
}


size_t DebugProcessView::PerformWrite(uint64_t offset, const void* data, size_t len)
{
    std::unique_lock<std::mutex> memoryLock(m_memoryMutex);

    Ref<BinaryView> parentView = GetParentView();
    if (!parentView)
        return 0;

    DebuggerState* state = DebuggerState::GetState(parentView);
    if (!state)
        return 0;

    DebugAdapter* adapter = state->GetAdapter();
    if (!adapter)
        return 0;

    // Assume any memory change invalidates all of memory (suboptimal, may not be necessary)
    MarkDirty();

    if (adapter->WriteMemory(offset, data, len))
        return len;

    return 0;
}


void DebugProcessView::MarkDirty()
{
    m_valueCache.clear();
    m_errorCache.clear();
}
