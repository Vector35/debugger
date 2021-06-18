#include "processview.h"

DebugMemoryView::DebugMemoryView(BinaryViewRef parent):
    BinaryView("Debugged Process Memory", parent->GetFile(), parent)
{
    m_arch = parent->GetDefaultArchitecture();
    m_platform = parent->GetDefaultPlatform();
}