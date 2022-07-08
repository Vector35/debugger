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

#include "remoteprocess.h"

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;

RemoteProcessSettingsDialog::RemoteProcessSettingsDialog(QWidget* parent, DebuggerController* controller): QDialog()
{
    setWindowTitle("Remote Process Settings");
    setMinimumSize(UIContext::getScaledWindowSize(400, 130));
    setAttribute(Qt::WA_DeleteOnClose);

    m_controller = controller;

    setModal(true);
    QVBoxLayout* layout = new QVBoxLayout;
    layout->setSpacing(0);

    QHBoxLayout* titleLayout = new QHBoxLayout;
    titleLayout->setContentsMargins(0, 0, 0, 0);

    m_pluginEntry = new QComboBox(this);
    auto pluginsMetadata = m_controller->GetAdapterProperty("process_plugins");
    if (pluginsMetadata && pluginsMetadata->IsStringList())
    {
        auto plugins = pluginsMetadata->GetStringList();
        for (const auto& plugin: plugins)
            m_pluginEntry->addItem(QString::fromStdString(plugin));
    }

    auto currentPluginMetadata = m_controller->GetAdapterProperty("current_process_plugin");
    if (currentPluginMetadata && currentPluginMetadata->IsString())
    {
        const auto currentPlugin = currentPluginMetadata->GetString();
        m_pluginEntry->setCurrentText(QString::fromStdString(currentPlugin));
    }

    m_addressEntry = new QLineEdit(this);
    m_portEntry = new QLineEdit(this);

    QFormLayout* formLayout = new QFormLayout;
    formLayout->addRow("Plugin", m_pluginEntry);
    formLayout->addRow("Host", m_addressEntry);
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

    m_addressEntry->setText(QString::fromStdString(m_controller->GetRemoteHost()));
    m_portEntry->setText(QString::number(m_controller->GetRemotePort()));
}


void RemoteProcessSettingsDialog::apply()
{
    std::string host = m_addressEntry->text().toStdString();
    m_controller->SetRemoteHost(host);
    auto data = new Metadata(host);
    m_controller->GetData()->StoreMetadata("debugger.remote_host", data);

    std::string portString = m_portEntry->text().toStdString();
    uint64_t port;
    try
    {
        port = stoull(portString);
    }
    catch(const std::exception&)
    {
        port = 31337;
    }

    m_controller->SetRemotePort(port);
    data = new Metadata(port);
    m_controller->GetData()->StoreMetadata("debugger.remote_port", data);

	const auto plugin = m_pluginEntry->currentText().toStdString();
	if (!plugin.empty())
	{
		Ref<Metadata> pluginMetadata = new Metadata(plugin);
		m_controller->SetAdapterProperty("current_process_plugin", pluginMetadata);
		m_controller->GetData()->StoreMetadata("debugger.process_plugin", pluginMetadata);
	}

    accept();
}
