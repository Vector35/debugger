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

class AdapterSettingsDialog: public QDialog
{
    Q_OBJECT

private:
    DebuggerController* m_controller;
    QComboBox* m_adapterEntry;
    QLineEdit* m_pathEntry;
	QLineEdit* m_workingDirectoryEntry;
    QLineEdit* m_argumentsEntry;
    QLineEdit* m_addressEntry;
    QLineEdit* m_portEntry;
	QCheckBox* m_terminalEmulator;

public:
    AdapterSettingsDialog(QWidget* parent, DebuggerController* controller);

private Q_SLOTS:
    void apply();
    void selectAdapter(const QString& adapter);
};
