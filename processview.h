#include "binaryninjaapi.h"
#include "viewframe.h"

// The debug memory BinaryView layout is in a few pieces:
// - DebugProcessView represents the entire debugged process, containing segments for mapped memory
// - DebugMemoryView represents the raw memory of the process (eg like a raw BinaryView)

class DebugProcessView: public BinaryNinja::BinaryView
{
    DebugProcessView(BinaryViewRef parent);
};


class DebugMemoryView: public BinaryNinja::BinaryView
{
private:
    ArchitectureRef m_arch;
    PlatformRef m_platform;

public:
    DebugMemoryView(BinaryViewRef parent);
};
