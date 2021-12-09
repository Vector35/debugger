#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QCheckBox>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "../debuggerstate.h"
#include "../debuggercontroller.h"

class AdapterSettingsDialog: public QDialog
{
    Q_OBJECT

private:
    DebuggerController* m_controller;
    DebuggerState* m_state;

    QComboBox* m_adapterEntry;
    QLineEdit* m_pathEntry;
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
