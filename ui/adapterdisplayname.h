#pragma once

#include <QString>
#include <string>

// Keep presentation separate from API identifiers and database metadata.
inline QString DebugAdapterDisplayName(const std::string& identifier)
{
	return identifier == "X2WIN_RPC" ? QStringLiteral("Windows Remote") : QString::fromStdString(identifier);
}
