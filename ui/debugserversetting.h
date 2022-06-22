/*
Copyright 2020-2022 Vector 35 Inc.

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

#include <QDialog>
#include <QPushButton>
#include <QLineEdit>
#include <QComboBox>
#include <QFormLayout>
#include <QCheckBox>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "debuggerapi.h"

using namespace BinaryNinjaDebuggerAPI;

class DebugServerSettingsDialog: public QDialog
{
    Q_OBJECT

private:
    DebuggerController* m_controller;
    QLineEdit* m_addressEntry;
    QLineEdit* m_portEntry;

public:
    DebugServerSettingsDialog(QWidget* parent, DebuggerController* controller);

private Q_SLOTS:
    void apply();
};
