#include "adaptersettings.h"
#include "uicontext.h"
#include "../debuggercontroller.h"

using namespace BinaryNinja;
using namespace std;

AdapterSettingsDialog::AdapterSettingsDialog(QWidget* parent, BinaryViewRef data): QDialog()
{
    setWindowTitle("Debug Adapter Settings");
    setMinimumSize(UIContext::getScaledWindowSize(400, 130));
    setAttribute(Qt::WA_DeleteOnClose);

    m_controller = DebuggerController::GetController(data);
    m_state = m_controller->GetState();

    QVBoxLayout* layout = new QVBoxLayout;
    layout->setSpacing(0);

    QLabel* titleLabel = new QLabel("Adapter Settings");
    QHBoxLayout* titleLayout = new QHBoxLayout;
    titleLayout->setContentsMargins(0, 0, 0, 0);
    titleLayout->addWidget(titleLabel);

    m_adapterEntry = new QComboBox(this);
    for (DebugAdapterType::AdapterType adapter = DebugAdapterType::DefaultAdapterType;
        adapter <= DebugAdapterType::RemoteSenseAdapterType; adapter = (DebugAdapterType::AdapterType)(adapter + 1))
    {
//        if (!DebugAdapterType::CanUse(adapter))
//            continue;
//        m_adapterEntry->addItem(QString::fromStdString(DebugAdapterType::GetName(adapter)), (qulonglong)adapter);
//        if (adapter == m_state->GetAdapterType())
//            m_adapterEntry->setCurrentText(QString::fromStdString(DebugAdapterType::GetName(adapter)));
    }
    connect(m_adapterEntry, &QComboBox::currentIndexChanged, this, &AdapterSettingsDialog::selectAdapter);

    m_pathEntry = new QLineEdit(this);
    m_argumentsEntry = new QLineEdit(this);
    m_addressEntry = new QLineEdit(this);
    m_portEntry = new QLineEdit(this);

    QFormLayout* formLayout = new QFormLayout;
    formLayout->addRow("Adapter Type", m_adapterEntry);
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
    setLayout(layout);

    m_addressEntry->setText(QString::fromStdString(m_state->GetRemoteHost()));
    m_portEntry->setText(QString::number(m_state->GetRemotePort()));
    m_pathEntry->setText(QString::fromStdString(m_state->GetExecutablePath()));

    std::string args;
    std::vector<std::string> argList = m_state->GetCommandLineArguments();
    for (size_t i = 0; i < argList.size(); i++)
    {
        if (i != 0)
            args += ' ';

        args += argList[i];
    }
    m_argumentsEntry->setText(QString::fromStdString(args));
}


void AdapterSettingsDialog::selectAdapter()
{
    DebugAdapterType::AdapterType adapter = (DebugAdapterType::AdapterType)m_adapterEntry->currentData().toULongLong();
    if (DebugAdapterType::UseExec(adapter))
    {
        m_pathEntry->setEnabled(true);
        m_argumentsEntry->setEnabled(true);
        m_addressEntry->setEnabled(false);
        m_portEntry->setEnabled(false);
    }
    else
    {
        m_pathEntry->setEnabled(false);
        m_argumentsEntry->setEnabled(false);
        m_addressEntry->setEnabled(true);
        m_portEntry->setEnabled(true);
    }
}


void AdapterSettingsDialog::apply()
{
    DebugAdapterType::AdapterType adapter = (DebugAdapterType::AdapterType)m_adapterEntry->currentData().toULongLong();
    m_state->SetAdapterType(adapter);
    Ref<Metadata> data = new Metadata((uint64_t)adapter);
    m_controller->GetData()->StoreMetadata("native_debugger.adapter_type", data);

    std::vector<std::string> args;
    // We need better support for shell-style cmd arguments
    QStringList argList = m_argumentsEntry->text().split(" ");
    for (const QString& arg: argList)
    {
        args.push_back(arg.toStdString());
    }
    m_state->SetCommandLineArguments(args);
    // data = new Metadata(args);
    // m_data->StoreMetadata("native_debugger.command_line_args", data);

    std::string path = m_pathEntry->text().toStdString();
    m_state->SetExecutablePath(path);
    data = new Metadata(path);
    m_controller->GetData()->StoreMetadata("native_debugger.executable_path", data);

    std::string host = m_addressEntry->text().toStdString();
    m_state->SetRemoteHost(host);
    data = new Metadata(host);
    m_controller->GetData()->StoreMetadata("native_debugger.remote_host", data);

    std::string portString = m_portEntry->text().toStdString();
    uint64_t port;
    try
    {
        port = stoull(portString);

    }
    catch(const std::exception& e)
    {
        port = 31337;
    }
    
    m_state->SetRemotePort(port);
    data = new Metadata(port);
    m_controller->GetData()->StoreMetadata("native_debugger.remote_port", data);

    accept();
}
