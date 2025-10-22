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

#include <QPainter>
#include <QHeaderView>
#include <QLineEdit>
#include <QStatusBar>
#include <QLabel>
#include <QHBoxLayout>
#include "debuggerwidget.h"
#include "ui.h"

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;


DebuggerWidget::DebuggerWidget(const QString& name, ViewFrame* view, BinaryViewRef data) :
	SidebarWidget(name), m_view(view)
{
	m_controller = DebuggerController::GetController(data);

	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);
	layout->setAlignment(Qt::AlignTop);

	m_adapterSelector = new QComboBox();
	// Populate adapter selector
	for (const std::string& adapter : DebugAdapterType::GetAvailableAdapters(m_controller->GetData()))
	{
		m_adapterSelector->addItem(QString::fromStdString(adapter));
	}
	
	// Set current adapter
	if (!m_controller->GetAdapterType().empty())
	{
		m_adapterSelector->setCurrentText(QString::fromStdString(m_controller->GetAdapterType()));
	}
	else if (m_adapterSelector->count() > 0)
	{
		// Set first available adapter if none is set
		m_controller->SetAdapterType(m_adapterSelector->itemText(0).toStdString());
		m_adapterSelector->setCurrentIndex(0);
	}
	else
	{
		// No adapters available
		m_adapterSelector->addItem("(No available debug adapter)");
		m_adapterSelector->setEnabled(false);
	}
	
	connect(m_adapterSelector, &QComboBox::currentTextChanged, this, &DebuggerWidget::selectAdapter);
	
	layout->addWidget(m_adapterSelector);

	m_splitter = new QSplitter(Qt::Vertical, this);
	m_splitter->setChildrenCollapsible(true);

	m_controlsWidget = new DebugControlsWidget(this, "Controls", data);

	m_tabs = new QTabWidget(this);

	m_registersWidget = new DebugRegistersContainer(m_view, data, m_menu);
	m_breakpointsWidget = new DebugBreakpointsWidget(m_view, data, m_menu);

	m_tabs->addTab(m_registersWidget, "Registers");
	m_tabs->addTab(m_breakpointsWidget, "Breakpoints");

	m_splitter->addWidget(m_controlsWidget);
	m_splitter->addWidget(m_tabs);

	layout->addWidget(m_splitter);
	setLayout(layout);

	m_ui = DebuggerUI::GetForViewFrame(view);
	connect(m_ui, &DebuggerUI::debuggerEvent, this, &DebuggerWidget::uiEventHandler);
}


DebuggerWidget::~DebuggerWidget() {}


void DebuggerWidget::notifyFontChanged()
{
	m_registersWidget->updateFonts();
	m_breakpointsWidget->updateFonts();
}


void DebuggerWidget::updateContent()
{
	m_registersWidget->updateContent();
}


void DebuggerWidget::uiEventHandler(const DebuggerEvent& event)
{
	m_controlsWidget->updateButtons();
	
	// Enable adapter selector only when not connected
	DebugAdapterConnectionStatus connection = m_controller->GetConnectionStatus();
	if (m_adapterSelector->count() > 0 && m_adapterSelector->currentText() != "(No available debug adapter)")
	{
		m_adapterSelector->setEnabled(connection == DebugAdapterNotConnectedStatus);
	}
	
	switch (event.type)
	{
	case TargetStoppedEventType:
		// These updates ensure the widgets become empty after the target stops
	case DetachedEventType:
	case ActiveThreadChangedEvent:
	case RegisterChangedEvent:
		updateContent();
		break;
	case RelativeBreakpointAddedEvent:
	case AbsoluteBreakpointAddedEvent:
	case RelativeBreakpointRemovedEvent:
	case AbsoluteBreakpointRemovedEvent:
	case AbsoluteBreakpointEnabledEvent:
	case RelativeBreakpointEnabledEvent:
	case AbsoluteBreakpointDisabledEvent:
	case RelativeBreakpointDisabledEvent:
		m_breakpointsWidget->updateContent();
		break;
	default:
		break;
	}
}


void DebuggerWidget::selectAdapter(const QString& adapter)
{
	if (adapter.isEmpty())
		return;

	auto adapterType = DebugAdapterType::GetByName(adapter.toStdString());
	if (!adapterType)
		return;

	m_controller->SetAdapterType(adapter.toStdString());
	Ref<Metadata> data = new Metadata(adapter.toStdString());
	m_controller->GetData()->StoreMetadata("debugger.adapter_type", data);

	// Update button states after adapter change
	m_controlsWidget->updateButtons();
}
