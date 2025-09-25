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
	resize(400, 200);

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
	formLayout->addRow("Type:", m_typeCombo);

	// Size selection (for watchpoints)
	m_sizeSpin = new QSpinBox();
	m_sizeSpin->setMinimum(1);
	m_sizeSpin->setMaximum(8);
	m_sizeSpin->setValue(1);
	m_sizeSpin->setSuffix(" byte(s)");
	// Only allow powers of 2
	m_sizeSpin->setSpecialValueText("1 byte");
	formLayout->addRow("Size:", m_sizeSpin);

	// Help label
	m_helpLabel = new QLabel();
	m_helpLabel->setWordWrap(true);
	m_helpLabel->setStyleSheet("QLabel { color: gray; font-size: 10px; }");
	formLayout->addRow(m_helpLabel);

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
	return static_cast<size_t>(m_sizeSpin->value());
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
		bool success = m_controller->AddHardwareBreakpoint(address, type, size);
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
	
	if (!valid && !m_addressEdit->text().isEmpty())
	{
		m_helpLabel->setText("Please enter a valid hexadecimal address (e.g., 0x401000)");
		m_helpLabel->setStyleSheet("QLabel { color: red; font-size: 10px; }");
	}
	else
	{
		typeChanged(); // Update help text
	}
}

void HardwareBreakpointDialog::typeChanged()
{
	DebugBreakpointType type = getType();
	
	// Enable/disable size control based on type
	bool needSize = (type != HardwareExecuteBreakpoint);
	m_sizeSpin->setEnabled(needSize);
	
	// Update help text
	QString helpText;
	switch (type)
	{
		case HardwareExecuteBreakpoint:
			helpText = "Hardware execution breakpoint will trigger when the CPU executes code at the specified address.";
			m_sizeSpin->setValue(1); // Execution breakpoints are always 1 byte
			break;
		case HardwareReadBreakpoint:
			helpText = "Hardware read watchpoint will trigger when the CPU reads from the specified memory range.";
			break;
		case HardwareWriteBreakpoint:
			helpText = "Hardware write watchpoint will trigger when the CPU writes to the specified memory range.";
			break;
		case HardwareAccessBreakpoint:
			helpText = "Hardware access watchpoint will trigger when the CPU reads from or writes to the specified memory range.";
			break;
		default:
			helpText = "";
			break;
	}
	
	m_helpLabel->setText(helpText);
	m_helpLabel->setStyleSheet("QLabel { color: gray; font-size: 10px; }");
}