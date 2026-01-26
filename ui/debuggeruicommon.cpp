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

#include "debuggeruicommon.h"

using namespace BinaryNinja;

bool ParseAddress(const QString& text, BinaryNinja::Ref<BinaryNinja::BinaryView> data, uint64_t& result, std::string* errorMessage)
{
	QString cleanText = text.trimmed();
	if (cleanText.isEmpty())
	{
		if (errorMessage)
			*errorMessage = "Address string is empty";
		return false;
	}

	// First try WinDbg format - remove backticks (e.g., 000000dd`7e7fed80)
	QString cleanedText = cleanText;
	cleanedText.replace("`", "");

	bool ok = false;
	uint64_t address = 0;

	// Try parsing as hexadecimal first
	if (cleanedText.startsWith("0x", Qt::CaseInsensitive))
	{
		// Has 0x prefix, parse as hex
		address = cleanedText.mid(2).toULongLong(&ok, 16);
	}
	else
	{
		// Try parsing as hex without prefix
		address = cleanedText.toULongLong(&ok, 16);
	}

	// If simple parsing succeeded, return the result
	if (ok)
	{
		result = address;
		return true;
	}

	// If simple parsing failed, use Binary Ninja's expression parser
	// This supports symbols, expressions like "main+0x10", etc.
	std::string parseError;
	if (BinaryView::ParseExpression(data, text.toStdString(), address, 0, parseError))
	{
		result = address;
		return true;
	}

	// All parsing methods failed
	if (errorMessage)
		*errorMessage = parseError.empty() ? "Failed to parse address" : parseError;

	return false;
}
