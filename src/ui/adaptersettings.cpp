#include "adaptersettings.h"
#include "uicontext.h"

using namespace BinaryNinja;
using namespace std;

AdapterSettingsDialog::AdapterSettingsDialog(QWidget* parent, BinaryViewRef data): QDialog(), m_data(data)
{
    setWindowTitle("Debug Adapter Settings");
    setMinimumSize(UIContext::getScaledWindowSize(400, 130));
    setAttribute(Qt::WA_DeleteOnClose);

    QVBoxLayout* layout = new QVBoxLayout;
    layout->setSpacing(0);

    QLabel* titleLabel = new QLabel("Adapter Settings");
    QHBoxLayout* titleLayout = new QHBoxLayout;
    titleLayout->setContentsMargins(0, 0, 0, 0);
    titleLayout->addWidget(titleLabel);

    m_adapterEntry = new QPushButton(this);
    m_adapterMenu = new QMenu(this);

    for (DebugAdapterType::AdapterType adapter = DebugAdapterType::DefaultAdapterType;
        adapter <= DebugAdapterType::RemoteSenseAdapterType; adapter = (DebugAdapterType::AdapterType)(adapter + 1))
    {
        if (!DebugAdapterType::CanUse(adapter))
            continue;
        m_adapterMenu->addAction(QString::fromStdString(DebugAdapterType::GetName(adapter)),
            [&](){ selectAdapter(adapter); });
        if (adapter == m_state->getAdapterType())
            m_adapterEntry->setText(QString::fromStdString(DebugAdapterType::GetName(adapter)));
    }

    m_adapterEntry->setMenu(m_adapterMenu);

    m_pathEntry = new QLineEdit(this);
    m_argumentsEntry = new QLineEdit(this);
    m_addressEntry = new QLineEdit(this);
    m_portEntry = new QLineEdit(this);

    QFormLayout* formLayout = new QFormLayout;
    formLayout->addRow("Adapter Type", m_addressEntry);
    formLayout->addRow("Executable Path", m_pathEntry);
    formLayout->addRow("Command Line Arguments", m_argumentsEntry);
    formLayout->addRow("Address", m_addressEntry);
    formLayout->addRow("Port", m_portEntry);

    QHBoxLayout* buttonLayout = new QHBoxLayout;
    buttonLayout->setContentsMargins(0, 0, 0, 0);

    QPushButton* cancelButton = new QPushButton("Cancel");
    connect(cancelButton, &QPushButton::clicked, [&](){ reject(); });
    QPushButton* acceptButton = new QPushButton("Accept");
    connect(acceptButton, &QPushButton::clicked, [&](){ apply(); });
    acceptButton->setDefault(true);

    buttonLayout->addStretch(1);
    buttonLayout->addWidget(cancelButton);
    buttonLayout->addWidget(acceptButton);

    layout->addLayout(titleLayout);
    layout->addSpacing(10);
    layout->addLayout(formLayout);
    layout->addStretch(1);
    layout->addSpacing(10);
    layout->addLayout(buttonLayout);

    m_addressEntry->setText(QString::fromStdString(m_state->getRemoteHost()));
    m_addressEntry->setText(QString::number(m_state->getRemotePort()));
}


void AdapterSettingsDialog::selectAdapter(DebugAdapterType::AdapterType adapter)
{

}


void AdapterSettingsDialog::apply()
{
    accept();
}
