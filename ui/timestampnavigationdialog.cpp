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

#include "timestampnavigationdialog.h"
#include <QMessageBox>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QGroupBox>

TimestampNavigationDialog::TimestampNavigationDialog(QWidget* parent, DbgRef<DebuggerController> controller)
	: QDialog(parent), m_controller(controller)
{
	setWindowTitle("Navigate to TTD Timestamp");
	setModal(true);

	// Main layout
	QVBoxLayout* mainLayout = new QVBoxLayout(this);

	// Navigation group
	QGroupBox* navGroup = new QGroupBox("Navigate to Position", this);
	QFormLayout* navLayout = new QFormLayout(navGroup);

	m_timestampEdit = new QLineEdit(this);
	m_timestampEdit->setPlaceholderText("e.g., 1A0:12F");
	m_timestampEdit->setFont(QFont("monospace"));
	
	// Add input validation for hex:hex format
	QRegularExpression regex("^[0-9A-Fa-f]+:[0-9A-Fa-f]+$");
	QRegularExpressionValidator* validator = new QRegularExpressionValidator(regex, this);
	m_timestampEdit->setValidator(validator);
	
	navLayout->addRow("Timestamp (Sequence:Step):", m_timestampEdit);

	m_helpLabel = new QLabel("Enter timestamp in hex format: SEQUENCE:STEP", this);
	m_helpLabel->setStyleSheet("color: gray; font-size: 10px;");
	navLayout->addRow(m_helpLabel);

	mainLayout->addWidget(navGroup);

	// Button box
	m_buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
	m_buttonBox->button(QDialogButtonBox::Ok)->setText("Navigate");
	m_buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
	
	mainLayout->addWidget(m_buttonBox);

	// Connect signals
	connect(m_buttonBox, &QDialogButtonBox::accepted, this, &TimestampNavigationDialog::navigate);
	connect(m_buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(m_timestampEdit, &QLineEdit::textChanged, this, &TimestampNavigationDialog::validateInput);

	// Initialize current position and fill timestamp field
	initializePositions();
}

void TimestampNavigationDialog::initializePositions()
{
	if (!m_controller || !m_controller->IsTTD())
	{
		return;
	}

	TTDPosition current = m_controller->GetCurrentTTDPosition();
	QString positionText = QString("%1:%2")
		.arg(current.sequence, 0, 16)
		.arg(current.step, 0, 16);
	
	// Fill the timestamp edit field with current position
	m_timestampEdit->setText(positionText.toUpper());
	
	// Select all text so user can immediately paste a new timestamp or copy the current one
	m_timestampEdit->selectAll();
}

void TimestampNavigationDialog::validateInput()
{
	QString text = m_timestampEdit->text().trimmed();
	bool valid = !text.isEmpty() && text.contains(':');
	
	if (valid)
	{
		QStringList parts = text.split(':');
		if (parts.size() == 2)
		{
			bool ok1, ok2;
			parts[0].toULongLong(&ok1, 16);
			parts[1].toULongLong(&ok2, 16);
			valid = ok1 && ok2;
		}
		else
		{
			valid = false;
		}
	}
	
	m_buttonBox->button(QDialogButtonBox::Ok)->setEnabled(valid);
}

void TimestampNavigationDialog::navigate()
{
	if (!m_controller)
	{
		QMessageBox::warning(this, "Error", "No debugger controller available.");
		return;
	}

	if (!m_controller->IsTTD())
	{
		QMessageBox::warning(this, "Error", "Time travel debugging is not active.");
		return;
	}

	QString timestampStr = m_timestampEdit->text().trimmed();
	QStringList parts = timestampStr.split(':');
	
	if (parts.size() != 2)
	{
		QMessageBox::warning(this, "Error", "Invalid timestamp format. Use SEQUENCE:STEP format.");
		return;
	}

	bool ok1, ok2;
	uint64_t sequence = parts[0].toULongLong(&ok1, 16);
	uint64_t step = parts[1].toULongLong(&ok2, 16);

	if (!ok1 || !ok2)
	{
		QMessageBox::warning(this, "Error", "Invalid hexadecimal values in timestamp.");
		return;
	}

	TTDPosition targetPos(sequence, step);
	
	// Get current position and check if it's the same
	TTDPosition currentPos = m_controller->GetCurrentTTDPosition();
	if (targetPos.sequence == currentPos.sequence && targetPos.step == currentPos.step)
	{
		// Same position, just close the dialog without navigating
		accept();
		return;
	}
	
	if (m_controller->SetTTDPosition(targetPos))
	{
		accept();
	}
	else
	{
		QMessageBox::warning(this, "Error", "Failed to navigate to the specified timestamp.\nThe position might be invalid or out of range.");
	}
}