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

#include <QWidget>
#include <QTableWidget>

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
    uint64_t m_numericValue;
};
