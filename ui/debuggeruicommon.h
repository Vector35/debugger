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

#include <QWidget>
#include <QTableWidget>
#include <QString>
#include <string>
#include "binaryninjaapi.h"

// Custom table widget item that supports numerical sorting
class NumericalTableWidgetItem : public QTableWidgetItem
{
public:
    NumericalTableWidgetItem(const QString& text, uint64_t numericValue)
        : QTableWidgetItem(text), m_numericValue(numericValue)
    {
        setData(Qt::UserRole, static_cast<qulonglong>(numericValue));
    }

    bool operator<(const QTableWidgetItem& other) const override
    {
        // Use the numeric value stored in UserRole for sorting
        return data(Qt::UserRole).toULongLong() < other.data(Qt::UserRole).toULongLong();
    }

private:
    [[maybe_unused]] uint64_t m_numericValue;
};

// Parse an address from a QString, supporting multiple formats:
// - WinDbg format with backticks (e.g., "000000dd`7e7fed80")
// - Hexadecimal with 0x prefix (e.g., "0x1000")
// - Plain hexadecimal (e.g., "1000")
// - Binary Ninja expressions (e.g., "main+0x10", "ImageBase+0x1000")
//
// Returns true if parsing succeeded and sets 'result' to the parsed address.
// Returns false if parsing failed.
bool ParseAddress(const QString& text, BinaryNinja::Ref<BinaryNinja::BinaryView> data, uint64_t& result, std::string* errorMessage = nullptr);

// Navigate to `target` from a debugger sidebar widget, choosing the pane by content type.
//
// If the current pane and `target` are the same kind of thing -- both inside a function
// (code), or both outside one (data) -- navigate the current pane in place, like an
// ordinary jump. If they differ, open `target` in the other pane so what the user is
// looking at stays visible. Because a data target then matches the (data) companion pane,
// subsequent data double-clicks reuse that pane instead of bouncing back to the code pane;
// that is what keeps repeated double-clicks from drifting. Falls back to the current pane
// when there is no other pane available.
//
// `widget` is any widget inside the window whose current view should be navigated from.
void NavigateToAddress(QWidget* widget, BinaryNinja::Ref<BinaryNinja::BinaryView> data, uint64_t target);

// Navigate to `target` in the currently focused pane, in place, unconditionally. This is
// the "force it into the pane I have focused" fallback exposed via the right-click menu.
void NavigateToAddressInCurrentPane(
    QWidget* widget, BinaryNinja::Ref<BinaryNinja::BinaryView> data, uint64_t target);
