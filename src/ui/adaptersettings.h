#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QFormLayout>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "../debuggerstate.h"

class AdapterSettingsDialog: public QDialog
{
    Q_OBJECT

private:
    BinaryViewRef m_data;
    DebuggerState* m_state;

    QPushButton* m_adapterEntry;
    QMenu* m_adapterMenu;

    QLineEdit* m_pathEntry;
    QLineEdit* m_argumentsEntry;
    QLineEdit* m_addressEntry;
    QLineEdit* m_portEntry;


public:
    AdapterSettingsDialog(QWidget* parent, BinaryViewRef data);
    void selectAdapter(DebugAdapterType::AdapterType adapter);

private Q_SLOTS:
    void apply();
};
