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

#include "debugserversetting.h"
#include "progresstask.h"

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;

DebugServerSettingsDialog::DebugServerSettingsDialog(QWidget* parent, DebuggerControllerRef controller):
	QDialog(), m_controller(controller)
{
    setWindowTitle("Debug Server Settings");
    setMinimumSize(UIContext::getScaledWindowSize(600, 130));
    setAttribute(Qt::WA_DeleteOnClose);

    setModal(true);
    QVBoxLayout* layout = new QVBoxLayout;
    layout->setSpacing(0);

    QHBoxLayout* titleLayout = new QHBoxLayout;
    titleLayout->setContentsMargins(0, 0, 0, 0);

    m_platformEntry = new QComboBox(this);
    auto platformsMetaData = m_controller->GetAdapterProperty("platforms");
    if (platformsMetaData && platformsMetaData->IsStringList())
    {
        auto platforms = platformsMetaData->GetStringList();
        for (const auto& platform: platforms)
            m_platformEntry->addItem(QString::fromStdString(platform));
    }

    auto currentPlatformMetadata = m_controller->GetAdapterProperty("current_platform");
    if (currentPlatformMetadata && currentPlatformMetadata->IsString())
    {
        const auto currentPlatform = currentPlatformMetadata->GetString();
        m_platformEntry->setCurrentText(QString::fromStdString(currentPlatform));
    }

    m_addressEntry = new QLineEdit(this);
    m_portEntry = new QLineEdit(this);

    QFormLayout* formLayout = new QFormLayout;
    formLayout->addRow("Platform", m_platformEntry);
    formLayout->addRow("Host", m_addressEntry);
    formLayout->addRow("Port", m_portEntry);

	auto *bottomRowLayout = new QHBoxLayout();

    QHBoxLayout* buttonLayout = new QHBoxLayout;
    buttonLayout->setContentsMargins(0, 0, 0, 0);

    QPushButton* cancelButton = new QPushButton("Cancel");
    connect(cancelButton, &QPushButton::clicked, [&](){ reject(); });
    m_acceptButton = new QPushButton("Connect");
    connect(m_acceptButton, &QPushButton::clicked, [&](){ apply(); });
	m_acceptButton->setDefault(true);

    buttonLayout->addStretch(1);
    buttonLayout->addWidget(cancelButton);
    buttonLayout->addWidget(m_acceptButton);

	auto* hintLayout = new QHBoxLayout();

	m_hintLabel = new QLabel("");
	QPalette labelPalette;
	labelPalette.setColor(m_hintLabel->foregroundRole(), getThemeColor(ScriptConsoleOutputColor));
	m_hintLabel->setPalette(labelPalette);

	m_hintIcon = new QLabel("");
	QIcon icon = style()->standardIcon(QStyle::SP_MessageBoxInformation);
	QPixmap pixmap = icon.pixmap(QSize(fontMetrics().height(), fontMetrics().height()));
	m_hintIcon->setPixmap(pixmap);

	resetHintMessages();

	hintLayout->addWidget(m_hintIcon, 0, Qt::AlignRight);
	hintLayout->addWidget(m_hintLabel, 0, Qt::AlignLeft);

	hintLayout->setAlignment(Qt::AlignLeft);
	buttonLayout->setAlignment(Qt::AlignRight);

	bottomRowLayout->addLayout(hintLayout);
	bottomRowLayout->addLayout(buttonLayout);

	layout->addLayout(titleLayout);
	layout->addSpacing(10);
	layout->addLayout(formLayout);
	layout->addStretch(1);
	layout->addSpacing(10);

	layout->addLayout(bottomRowLayout);

    setLayout(layout);

    m_addressEntry->setText(QString::fromStdString(m_controller->GetRemoteHost()));
    m_portEntry->setText(QString::number(m_controller->GetRemotePort()));
}


void DebugServerSettingsDialog::apply()
{
    std::string host = m_addressEntry->text().toStdString();
    m_controller->SetRemoteHost(host);
    Ref<Metadata> data = new Metadata(host);
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

	const auto platform = m_platformEntry->currentText().toStdString();
	if (!platform.empty())
	{
		data = new Metadata(platform);
		m_controller->SetAdapterProperty("current_platform", data);
		m_controller->GetData()->StoreMetadata("debugger.platform", data);
	}

	BackgroundThread::create()
		->thenMainThread([=](QVariant) {
			displayInfoWithText("Connecting...");
			m_acceptButton->setEnabled(false);
			m_closeBlocking = true;
		})
		->thenBackground([=](QVariant) {
			return m_controller->ConnectToDebugServer(); // This can block UI on failure.
		})
		->thenMainThread([=](QVariant var) {
			m_acceptButton->setEnabled(true);
			m_closeBlocking = false;
			if (var.value<bool>() && m_controller->IsConnected())
				accept();
			else
				displayErrorWithText("Could not connect.");
		})
		->catchMainThread([=](std::exception_ptr exc) {
			try {
				std::rethrow_exception(exc);
			}
			catch (std::exception e) {
				LogError("Failed to connect with exception %s", e.what());
				displayErrorWithText("Could not connect.");
				m_acceptButton->setEnabled(true);
				m_closeBlocking = false;
			}
		})->start();
}

void DebugServerSettingsDialog::reject()
{
	if (!m_closeBlocking)
		QDialog::reject();
}

void DebugServerSettingsDialog::displayInfoWithText(const QString& text) const
{
	QIcon icon = style()->standardIcon(QStyle::SP_MessageBoxInformation);
	QPixmap pixmap = icon.pixmap(QSize(fontMetrics().height(), fontMetrics().height()));
	m_hintIcon->setPixmap(pixmap);

	QPalette labelPalette;
	labelPalette.setColor(m_hintLabel->foregroundRole(), getThemeColor(ScriptConsoleOutputColor));
	m_hintLabel->setPalette(labelPalette);

	m_hintLabel->setText(text);
	m_hintIcon->setVisible(true);
	m_hintLabel->setVisible(true);
}

void DebugServerSettingsDialog::displayWarningWithText(const QString &text) const
{
	QIcon icon = style()->standardIcon(QStyle::SP_MessageBoxWarning);
	QPixmap pixmap = icon.pixmap(QSize(fontMetrics().height(), fontMetrics().height()));
	m_hintIcon->setPixmap(pixmap);

	QPalette labelPalette;
	labelPalette.setColor(m_hintLabel->foregroundRole(), getThemeColor(ScriptConsoleWarningColor));
	m_hintLabel->setPalette(labelPalette);

	m_hintLabel->setText(text);
	m_hintIcon->setVisible(true);
	m_hintLabel->setVisible(true);
}

void DebugServerSettingsDialog::displayErrorWithText(const QString &text, bool disableAcceptanceButton) const
{
	QIcon icon = style()->standardIcon(QStyle::SP_MessageBoxCritical);
	QPixmap pixmap = icon.pixmap(QSize(fontMetrics().height(), fontMetrics().height()));
	m_hintIcon->setPixmap(pixmap);

	QPalette labelPalette;
	labelPalette.setColor(m_hintLabel->foregroundRole(), getThemeColor(ScriptConsoleErrorColor));
	m_hintLabel->setPalette(labelPalette);

	m_hintLabel->setText(text);
	m_hintIcon->setVisible(true);
	m_hintLabel->setVisible(true);

	if (disableAcceptanceButton)
		m_acceptButton->setEnabled(false);
}

void DebugServerSettingsDialog::resetHintMessages()
{
	m_hintLabel->setText("");
	m_hintIcon->setVisible(false);
	m_hintLabel->setVisible(false);
	m_acceptButton->setEnabled(true);
}

