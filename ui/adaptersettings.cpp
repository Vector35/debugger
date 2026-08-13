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

#include "adaptersettings.h"
#include "uicontext.h"
#include "qfiledialog.h"
#include "settingsview.h"
#include <QMessageBox>
#include <filesystem>

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;

AdapterSettingsDialog::AdapterSettingsDialog(QWidget* parent, DbgRef<DebuggerController> controller, const std::string& highlightGroup) :
	QDialog(), m_controller(controller), m_highlightGroup(highlightGroup)
{
	setWindowTitle("Debug Adapter Settings");
	setAttribute(Qt::WA_DeleteOnClose);

	setModal(true);
	resize(QSize(1200, 800));
	QVBoxLayout* layout = new QVBoxLayout;
	layout->setSpacing(0);

	m_adapterEntry = new QComboBox(this);
	for (const std::string& adapter : DebugAdapterType::GetAvailableAdapters(m_controller->GetData()))
	{
		m_adapterEntry->addItem(QString::fromStdString(adapter));
	}
	if (!m_controller->GetAdapterType().empty())
	{
		m_adapterEntry->setCurrentText(QString::fromStdString(m_controller->GetAdapterType()));
	}
	else
	{
		m_adapterEntry->setCurrentText("(No available debug adapter)");
	}

	connect(m_adapterEntry, &QComboBox::currentTextChanged, this, &AdapterSettingsDialog::selectAdapter);

	QHBoxLayout* adapterLayout = new QHBoxLayout();
	auto adapterLabel = new QLabel("Debug adapter: ");
	adapterLayout->addWidget(adapterLabel);
	adapterLayout->addWidget(m_adapterEntry);
	adapterLayout->addStretch(1);

	layout->addLayout(adapterLayout);

	m_noSettingsLabel = new QLabel("No settings available for the current adapter");
	m_noSettingsLabel->setAlignment(Qt::AlignCenter);
	m_stack = new QStackedWidget(this);
	m_stack->addWidget(m_noSettingsLabel);

	auto widget = getWidgetForAdapter(m_adapterEntry->currentText());
	m_stack->setCurrentWidget(widget);
	layout->addWidget(m_stack);

	// Reflect the stored preference: checked means "do not show the dialog next time"
	m_useSameSettingsCheckbox = new QCheckBox("Use same settings next time");
	m_useSameSettingsCheckbox->setChecked(!m_controller->ShowAdapterSettingsNextTime());

	if (!highlightGroup.empty())
	{
		auto adapterSettings = qobject_cast<SettingsView*>(widget);
		if (adapterSettings)
		{
			adapterSettings->setDefaultGroupSelection(QString::fromStdString(highlightGroup));
		}

		QHBoxLayout* buttonLayout = new QHBoxLayout;
		buttonLayout->setContentsMargins(0, 0, 0, 0);

		QPushButton* cancelButton = new QPushButton("Cancel");
		connect(cancelButton, &QPushButton::clicked, [&]() { reject(); });
		QPushButton* acceptButton = new QPushButton("Accept");
		connect(acceptButton, &QPushButton::clicked, [&]() { apply(); });
		acceptButton->setDefault(true);

		buttonLayout->addWidget(m_useSameSettingsCheckbox);
		buttonLayout->addStretch(1);
		buttonLayout->addWidget(cancelButton);
		buttonLayout->addSpacing(10);
		buttonLayout->addWidget(acceptButton);

		layout->addSpacing(10);
		layout->addLayout(buttonLayout);
	}
	else
	{
		// The generic settings dialog (opened from the menu) has no Accept/Cancel button and applies
		// settings live, so update the preference immediately whenever the checkbox is toggled. This is
		// the entry point for re-enabling the dialog after it has been suppressed for an operation.
		connect(m_useSameSettingsCheckbox, &QCheckBox::toggled, this,
			[this](bool checked) { m_controller->SetShowAdapterSettingsNextTime(!checked); });

		QHBoxLayout* checkboxLayout = new QHBoxLayout;
		checkboxLayout->setContentsMargins(0, 0, 0, 0);
		checkboxLayout->addWidget(m_useSameSettingsCheckbox);
		checkboxLayout->addStretch(1);

		layout->addSpacing(10);
		layout->addLayout(checkboxLayout);
	}

	setLayout(layout);
}


void AdapterSettingsDialog::selectAdapter(const QString& adapter)
{
	auto adapterType = DebugAdapterType::GetByName(adapter.toStdString());
	if (!adapterType)
		return;

	m_controller->SetAdapterType(adapter.toStdString());
	Ref<Metadata> data = new Metadata(adapter.toStdString());
	m_controller->GetData()->StoreMetadata("debugger.adapter_type", data);

	auto widget = getWidgetForAdapter(adapter);
	m_stack->setCurrentWidget(widget);
}


QWidget* AdapterSettingsDialog::getWidgetForAdapter(const QString& adapter)
{
	// I know this looks odd that we do not need to use the adapter parameter here. The reason is that we must call
	// SetAdapterType to set the active adapter before we can try to get its adapter settings object, so there is no
	// need to do it again here
	(void)adapter;

	if (m_viewMap.contains(adapter))
		return m_viewMap[adapter];

	auto adapterSettings = m_controller->GetAdapterSettings();
	if (adapterSettings)
	{
		auto settingsView = new SettingsView(this, adapterSettings);
		settingsView->setScope(SettingsResourceScope);
        settingsView->setData(m_controller->GetData());
		m_viewMap[adapter] = settingsView;
		m_stack->addWidget(settingsView);
		return settingsView;
	}

	return m_noSettingsLabel;
}


// The settings view writes each value as it is edited, so the current values can be read straight back from the
// adapter settings here. Only the settings whose absence is guaranteed to fail the operation are checked, so that
// the dialog does not get in the way of anything the adapter itself is willing to accept.
bool AdapterSettingsDialog::validateSettings()
{
	if ((m_highlightGroup != "launch") || (m_adapterEntry->currentText() != "DBGENG_TTD"))
		return true;

	auto adapterSettings = m_controller->GetAdapterSettings();
	if (!adapterSettings)
		return true;

	BNSettingsScope scope = SettingsResourceScope;
	auto tracePath = adapterSettings->Get<std::string>("launch.trace_path", m_controller->GetData(), &scope);
	if (tracePath.empty())
	{
		QMessageBox::warning(this, "No Trace Specified",
			"The TTD adapter replays a previously recorded trace, so a trace path is required.\n\n"
			"Set \"Trace Path\" in the launch settings, or record a new trace first.");
		return false;
	}

	std::error_code ec;
	if (!std::filesystem::is_regular_file(tracePath, ec))
	{
		if (!std::filesystem::exists(tracePath, ec))
		{
			QMessageBox::warning(this, "Trace Not Found",
				QString("The trace file\n\n%1\n\ndoes not exist. Set \"Trace Path\" in the launch settings to an "
					"existing trace.").arg(QString::fromStdString(tracePath)));
		}
		else
		{
			QMessageBox::warning(this, "Invalid Trace",
				QString("The trace path\n\n%1\n\nis not a file. Set \"Trace Path\" in the launch settings to a "
					"recorded trace file.").arg(QString::fromStdString(tracePath)));
		}
		return false;
	}

	return true;
}


void AdapterSettingsDialog::apply()
{
	if (!validateSettings())
		return;

	if (m_useSameSettingsCheckbox)
		m_controller->SetShowAdapterSettingsNextTime(!m_useSameSettingsCheckbox->isChecked());
	accept();
}
