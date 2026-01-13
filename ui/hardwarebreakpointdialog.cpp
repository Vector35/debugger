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

#include "hardwarebreakpointdialog.h"
#include <QMessageBox>
#include <QGridLayout>

HardwareBreakpointDialog::HardwareBreakpointDialog(QWidget* parent, DbgRef<DebuggerController> controller, uint64_t suggestedAddress) :
	QDialog(parent), m_controller(controller), m_suggestedAddress(suggestedAddress)
{
	setWindowTitle("Add Hardware Breakpoint");
	setModal(true);
	resize(350, 150);

	// Create form layout
	QFormLayout* formLayout = new QFormLayout();

	// Address input
	m_addressEdit = new QLineEdit();
	if (suggestedAddress != 0)
		m_addressEdit->setText(QString("0x%1").arg(suggestedAddress, 0, 16));
	formLayout->addRow("Address:", m_addressEdit);

	// Type selection
	m_typeCombo = new QComboBox();
	m_typeCombo->addItem("Hardware Execute", static_cast<int>(HardwareExecuteBreakpoint));
	m_typeCombo->addItem("Hardware Read", static_cast<int>(HardwareReadBreakpoint));
	m_typeCombo->addItem("Hardware Write", static_cast<int>(HardwareWriteBreakpoint));
	m_typeCombo->addItem("Hardware Access (Read/Write)", static_cast<int>(HardwareAccessBreakpoint));

	// Set default type based on whether there's a function at the address
	if (suggestedAddress != 0 && controller)
	{
		auto binaryView = controller->GetData();
		if (binaryView)
		{
			auto functions = binaryView->GetAnalysisFunctionsContainingAddress(suggestedAddress);
			if (functions.empty())
			{
				// No function at address - default to Hardware Read
				m_typeCombo->setCurrentIndex(1);
			}
			// else: function exists - default to Hardware Execute (already index 0)
		}
	}

	formLayout->addRow("Type:", m_typeCombo);

	// Size selection (for watchpoints)
	m_sizeCombo = new QComboBox();
	m_sizeCombo->setEditable(true);
	m_sizeCombo->addItem("1", 1);
	m_sizeCombo->addItem("2", 2);
	m_sizeCombo->addItem("4", 4);
	m_sizeCombo->addItem("8", 8);
	m_sizeCombo->setCurrentIndex(0);
	formLayout->addRow("Size:", m_sizeCombo);

	// Button box
	m_buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
	
	// Main layout
	QVBoxLayout* mainLayout = new QVBoxLayout();
	mainLayout->addLayout(formLayout);
	mainLayout->addWidget(m_buttonBox);
	setLayout(mainLayout);

	// Connect signals
	connect(m_buttonBox, &QDialogButtonBox::accepted, this, &HardwareBreakpointDialog::addBreakpoint);
	connect(m_buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(m_addressEdit, &QLineEdit::textChanged, this, &HardwareBreakpointDialog::validateInput);
	connect(m_typeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &HardwareBreakpointDialog::typeChanged);

	// Initial setup
	typeChanged();
	validateInput();
}

uint64_t HardwareBreakpointDialog::getAddress() const
{
	QString text = m_addressEdit->text().trimmed();
	if (text.startsWith("0x") || text.startsWith("0X"))
		text = text.mid(2);
	
	bool ok;
	uint64_t address = text.toULongLong(&ok, 16);
	return ok ? address : 0;
}

DebugBreakpointType HardwareBreakpointDialog::getType() const
{
	return static_cast<DebugBreakpointType>(m_typeCombo->currentData().toInt());
}

size_t HardwareBreakpointDialog::getSize() const
{
	bool ok;
	QString text = m_sizeCombo->currentText();
	size_t size = text.toULongLong(&ok);
	return ok ? size : 1;
}

void HardwareBreakpointDialog::addBreakpoint()
{
	uint64_t address = getAddress();
	if (address == 0)
	{
		QMessageBox::warning(this, "Invalid Address", "Please enter a valid hexadecimal address.");
		return;
	}

	DebugBreakpointType type = getType();
	size_t size = getSize();

	// Validate size for powers of 2
	if (type != HardwareExecuteBreakpoint && (size & (size - 1)) != 0)
	{
		QMessageBox::warning(this, "Invalid Size", "Watchpoint size must be a power of 2 (1, 2, 4, or 8 bytes).");
		return;
	}

	if (m_controller)
	{
		bool success = false;

		// Determine if we should use absolute or relative addressing
		bool isAbsoluteAddress = m_controller->IsConnected();

		if (isAbsoluteAddress)
		{
			// Use absolute address (target is connected, ASLR already applied)
			success = m_controller->AddHardwareBreakpoint(address, type, size);
		}
		else
		{
			// Use module+offset for ASLR safety (target not connected yet)
			std::string filename = m_controller->GetInputFile();
			uint64_t offset = address - m_controller->GetViewFileSegmentsStart();
			ModuleNameAndOffset info = {filename, offset};
			success = m_controller->AddHardwareBreakpoint(info, type, size);
		}

		if (success)
		{
			accept();
		}
		else
		{
			QMessageBox::warning(this, "Failed to Add Breakpoint",
				"Failed to add hardware breakpoint. The target may not support hardware breakpoints or all hardware breakpoint slots may be in use.");
		}
	}
}

void HardwareBreakpointDialog::validateInput()
{
	uint64_t address = getAddress();
	bool valid = (address != 0);

	m_buttonBox->button(QDialogButtonBox::Ok)->setEnabled(valid);
	typeChanged();
}

void HardwareBreakpointDialog::typeChanged()
{
	DebugBreakpointType type = getType();

	// Enable/disable size control based on type
	bool needSize = (type != HardwareExecuteBreakpoint);
	m_sizeCombo->setEnabled(needSize);

	// Execution breakpoints are always 1 byte
	if (type == HardwareExecuteBreakpoint)
		m_sizeCombo->setCurrentIndex(0);
}