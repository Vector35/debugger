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

#include "ttdnavigationwidget.h"
#include "debuggeruicommon.h"
#include "ui.h"
#include "theme.h"
#include "viewframe.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QApplication>
#include <QPixmap>
#include <algorithm>

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;


// Recolors one of the debugger's black and white icons to a theme color, the same way the
// control buttons above this widget do.
static QIcon getColoredIcon(const QString& iconPath, const QColor& color)
{
	auto pixmap = QPixmap(iconPath);
	auto mask = pixmap.createMaskFromColor(QColor(0, 0, 0), Qt::MaskInColor);
	pixmap.fill(color);
	pixmap.setMask(mask);
	return QIcon(pixmap);
}


TTDNavigationWidget::TTDNavigationWidget(QWidget* parent, BinaryViewRef data) : QWidget(parent), m_data(data)
{
	m_controller = DebuggerController::GetController(data);

	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(4, 2, 4, 2);
	layout->setSpacing(2);

	QHBoxLayout* targetLayout = new QHBoxLayout();
	targetLayout->setSpacing(4);
	targetLayout->addWidget(new QLabel("Target:"));

	m_targetEdit = new QLineEdit();
	m_targetEdit->setPlaceholderText("register or address range");
	m_targetEdit->setToolTip(
		"The register or memory range to navigate through. Follows the code view unless pinned. "
		"Ranges are written as \"start..end\".");
	connect(m_targetEdit, &QLineEdit::textEdited, this, &TTDNavigationWidget::targetEdited);
	connect(m_targetEdit, &QLineEdit::returnPressed, this, &TTDNavigationWidget::goToNext);
	targetLayout->addWidget(m_targetEdit);

	m_pinCheck = new QCheckBox("Pin");
	m_pinCheck->setFocusPolicy(Qt::NoFocus);
	m_pinCheck->setToolTip(
		"Pin the target so that it stays put.\n\n"
		"Unpinned, the target is whatever you have selected in the code view, so it moves along "
		"with the view as you time travel. Pin it to keep pressing Prev/Next on the same register "
		"or address range.");
	connect(m_pinCheck, &QCheckBox::toggled, this, &TTDNavigationWidget::pinToggled);
	targetLayout->addWidget(m_pinCheck);
	layout->addLayout(targetLayout);

	QHBoxLayout* actionLayout = new QHBoxLayout();
	actionLayout->setSpacing(4);

	m_readAccessCheck = new QCheckBox("R");
	m_readAccessCheck->setChecked(true);
	m_readAccessCheck->setFocusPolicy(Qt::NoFocus);
	m_readAccessCheck->setToolTip("Stop on reads of the memory range");
	m_writeAccessCheck = new QCheckBox("W");
	m_writeAccessCheck->setChecked(true);
	m_writeAccessCheck->setFocusPolicy(Qt::NoFocus);
	m_writeAccessCheck->setToolTip("Stop on writes to the memory range");
	m_executeAccessCheck = new QCheckBox("X");
	m_executeAccessCheck->setChecked(true);
	m_executeAccessCheck->setFocusPolicy(Qt::NoFocus);
	m_executeAccessCheck->setToolTip("Stop on execution of the memory range");
	actionLayout->addWidget(m_readAccessCheck);
	actionLayout->addWidget(m_writeAccessCheck);
	actionLayout->addWidget(m_executeAccessCheck);
	actionLayout->addStretch();

	// Wearing the TTD Memory sidebar's own icon, since pressing it is what opens that sidebar.
	m_showAllButton = new QToolButton();
	m_showAllButton->setIcon(getColoredIcon(":/debugger/ttd-memory", getThemeColor(CyanStandardHighlightColor)));
	m_showAllButton->setFocusPolicy(Qt::NoFocus);
	m_showAllButton->setToolTip("List every access to the target in the TTD Memory sidebar");
	connect(m_showAllButton, &QToolButton::clicked, this, &TTDNavigationWidget::showAllAccesses);
	actionLayout->addWidget(m_showAllButton);

	// Tool buttons rather than push buttons: they size themselves to the arrow instead of being
	// padded out to the style's minimum push button width.
	m_prevButton = new QToolButton();
	m_prevButton->setText("\xe2\x97\x80");
	m_prevButton->setFocusPolicy(Qt::NoFocus);
	m_prevButton->setToolTip("Time travel to the previous access of the target");
	connect(m_prevButton, &QToolButton::clicked, this, &TTDNavigationWidget::goToPrev);
	m_nextButton = new QToolButton();
	m_nextButton->setText("\xe2\x96\xb6");
	m_nextButton->setFocusPolicy(Qt::NoFocus);
	m_nextButton->setToolTip("Time travel to the next access of the target");
	connect(m_nextButton, &QToolButton::clicked, this, &TTDNavigationWidget::goToNext);
	actionLayout->addWidget(m_prevButton);
	actionLayout->addWidget(m_nextButton);
	layout->addLayout(actionLayout);

	m_statusLabel = new QLabel();
	m_statusLabel->setEnabled(false);
	m_statusLabel->hide();
	layout->addWidget(m_statusLabel);

	setLayout(layout);

	setTargetIsRegister(false);
	updateState();

	UIContext::registerNotification(this);
}


TTDNavigationWidget::~TTDNavigationWidget()
{
	UIContext::unregisterNotification(this);
}


void TTDNavigationWidget::OnNewSelectionForXref(
	UIContext* context, ViewFrame* frame, View* view, const SelectionInfoForXref& selection)
{
	if (context != UIContext::contextForWidget(this))
		return;

	updateTargetFromView(view);
}


void TTDNavigationWidget::updateState()
{
	bool isTTD = m_controller && m_controller->IsConnected() && m_controller->IsTTD();
	bool startingSession = isTTD && isHidden();
	setVisible(isTTD);

	if (!isTTD)
		return;

	if (startingSession)
	{
		// A fresh session starts over from whatever the user has selected. No notification is
		// coming to seed the target with at this point, so go and ask.
		m_pinCheck->setChecked(false);
		setStatus(QString());
		refreshTargetFromSelection();
	}

	updateNavigationButtons();
}


void TTDNavigationWidget::setTargetIsRegister(bool isRegister)
{
	m_targetIsRegister = isRegister;

	// The access type only applies to memory accesses; TTD reports register value changes
	// without any notion of read/write/execute. Listing every access is memory-only for the
	// same reason -- the TTD Memory sidebar has nothing to say about a register.
	m_readAccessCheck->setEnabled(!isRegister);
	m_writeAccessCheck->setEnabled(!isRegister);
	m_executeAccessCheck->setEnabled(!isRegister);
	m_showAllButton->setEnabled(!isRegister);
}


void TTDNavigationWidget::updateRegisterNames()
{
	if (!m_data)
		return;

	auto arch = m_data->GetDefaultArchitecture();
	if (!arch || (arch == m_registerNamesArch))
		return;

	m_registerNames.clear();
	for (uint32_t reg : arch->GetAllRegisters())
	{
		std::string name = arch->GetRegisterName(reg);
		std::transform(name.begin(), name.end(), name.begin(), ::tolower);
		m_registerNames.insert(name);
	}
	m_registerNamesArch = arch;
}


bool TTDNavigationWidget::isRegisterName(const std::string& text)
{
	updateRegisterNames();

	std::string lowered = text;
	std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::tolower);
	return m_registerNames.find(lowered) != m_registerNames.end();
}


void TTDNavigationWidget::pinToggled(bool pinned)
{
	if (!pinned)
		refreshTargetFromSelection();
}


void TTDNavigationWidget::refreshTargetFromSelection()
{
	UIContext* context = UIContext::contextForWidget(this);
	if (!context)
		return;

	updateTargetFromView(context->getCurrentView());
}


void TTDNavigationWidget::updateTargetFromView(View* view)
{
	if (!view || isHidden())
		return;

	// Do not fight the user over the target they picked, either by pinning it or by clicking
	// into the field to edit it.
	if (m_pinCheck->isChecked() || m_targetEdit->hasFocus())
		return;

	QString target;
	bool isRegister = false;

	auto token = view->getHighlightTokenState();
	if (token.valid && (token.type == RegisterToken) && !token.token.text.empty())
	{
		target = QString::fromStdString(token.token.text);
		isRegister = true;
	}
	else
	{
		// Same rule the "TTD Memory Access" context menu actions use: a non-empty selection is
		// the range, otherwise the single byte at the current address.
		auto selection = view->getSelectionOffsets();
		if (selection.start != selection.end)
			target = QString("0x%1..0x%2").arg(selection.start, 0, 16).arg(selection.end, 0, 16);
		else
			target = QString("0x%1").arg(view->getCurrentOffset(), 0, 16);
	}

	if ((target == m_targetEdit->text()) && (isRegister == m_targetIsRegister))
		return;

	m_targetEdit->setText(target);
	setTargetIsRegister(isRegister);
}


void TTDNavigationWidget::targetEdited(const QString& text)
{
	// The selection would otherwise overwrite what is being typed on the next click in the view.
	m_pinCheck->setChecked(true);
	setTargetIsRegister(isRegisterName(text.trimmed().toStdString()));
}


TTDMemoryAccessType TTDNavigationWidget::getSelectedAccessTypes()
{
	int accessType = 0;
	if (m_readAccessCheck->isChecked())
		accessType |= TTDMemoryRead;
	if (m_writeAccessCheck->isChecked())
		accessType |= TTDMemoryWrite;
	if (m_executeAccessCheck->isChecked())
		accessType |= TTDMemoryExecute;
	return static_cast<TTDMemoryAccessType>(accessType);
}


bool TTDNavigationWidget::parseMemoryTarget(uint64_t& address, uint64_t& size)
{
	QString text = m_targetEdit->text().trimmed();
	if (text.isEmpty())
		return false;

	// Ranges are written as "start..end"; " - " is accepted too since it reads more naturally.
	// Neither separator can appear in a single address expression, where "-" is subtraction.
	QString startText = text;
	QString endText;
	for (const QString& separator : {QString(".."), QString(" - ")})
	{
		int index = text.indexOf(separator);
		if (index < 0)
			continue;

		startText = text.left(index).trimmed();
		endText = text.mid(index + separator.size()).trimmed();
		break;
	}

	uint64_t start = 0;
	std::string error;
	if (!ParseAddress(startText, m_data, start, &error))
	{
		setStatus(QString("Invalid target: %1").arg(QString::fromStdString(error)));
		return false;
	}

	uint64_t end = start + 1;
	if (!endText.isEmpty() && !ParseAddress(endText, m_data, end, &error))
	{
		setStatus(QString("Invalid target: %1").arg(QString::fromStdString(error)));
		return false;
	}

	address = start;
	size = (end > start) ? (end - start) : 1;
	return true;
}


void TTDNavigationWidget::navigate(bool forward)
{
	if (!m_controller || !m_controller->IsConnected() || !m_controller->IsTTD())
	{
		setStatus("TTD is not available.");
		return;
	}

	std::string target = m_targetEdit->text().trimmed().toStdString();
	if (target.empty())
	{
		setStatus("Select a register or an address range to navigate.");
		return;
	}

	// The query runs on this thread and pumps the event loop while it waits, so keep the user
	// from starting a second one on top of it.
	m_prevButton->setEnabled(false);
	m_nextButton->setEnabled(false);

	if (m_targetIsRegister)
		navigateToRegisterWrite(target, forward);
	else
		navigateToMemoryAccess(forward);

	updateNavigationButtons();
}


void TTDNavigationWidget::setStatus(const QString& text)
{
	m_statusLabel->setText(text);
	m_statusLabel->setVisible(!text.isEmpty());
}


void TTDNavigationWidget::updateNavigationButtons()
{
	bool stopped = m_controller && m_controller->GetTargetStatus() != DebugAdapterRunningStatus;
	m_prevButton->setEnabled(stopped);
	m_nextButton->setEnabled(stopped);
	m_showAllButton->setEnabled(stopped && !m_targetIsRegister);
}


void TTDNavigationWidget::navigateToRegisterWrite(const std::string& reg, bool forward)
{
	setStatus(QString("Finding %1 write to %2...")
							   .arg(forward ? "next" : "previous")
							   .arg(QString::fromStdString(reg)));
	QApplication::processEvents();

	auto event = forward ? m_controller->GetTTDNextRegisterWrite(reg) : m_controller->GetTTDPrevRegisterWrite(reg);

	// A failed query (or a zero position) means there is no such write in the trace. Note that
	// TTD reports register value *changes*, so a write of the same value is not detected.
	if (!event || (event->position.sequence == 0 && event->position.step == 0))
	{
		setStatus(QString("No %1 write to %2 found.")
								   .arg(forward ? "next" : "previous")
								   .arg(QString::fromStdString(reg)));
		return;
	}

	if (!m_controller->SetTTDPosition(event->position))
	{
		setStatus("Found the write but failed to time travel to it.");
		return;
	}

	setStatus(QString("%1 = 0x%2 at %3:%4")
							   .arg(QString::fromStdString(reg))
							   .arg(event->value, 0, 16)
							   .arg(event->position.sequence, 0, 16)
							   .arg(event->position.step, 0, 16));
}


void TTDNavigationWidget::navigateToMemoryAccess(bool forward)
{
	TTDMemoryAccessType accessType = getSelectedAccessTypes();
	if (accessType == 0)
	{
		setStatus("Select at least one of R/W/X.");
		return;
	}

	uint64_t address = 0;
	uint64_t size = 0;
	if (!parseMemoryTarget(address, size))
		return;

	setStatus(QString("Finding %1 access...").arg(forward ? "next" : "previous"));
	QApplication::processEvents();

	auto [success, event] = forward ? m_controller->GetTTDNextMemoryAccess(address, size, accessType) :
									  m_controller->GetTTDPrevMemoryAccess(address, size, accessType);
	if (!success || (event.timeStart.sequence == 0 && event.timeStart.step == 0))
	{
		setStatus(
			QString("No %1 access to 0x%2 found.").arg(forward ? "next" : "previous").arg(address, 0, 16));
		return;
	}

	if (!m_controller->SetTTDPosition(event.timeStart))
	{
		setStatus("Found the access but failed to time travel to it.");
		return;
	}

	setStatus(QString("0x%1 accessed at %2:%3")
							   .arg(event.address, 0, 16)
							   .arg(event.timeStart.sequence, 0, 16)
							   .arg(event.timeStart.step, 0, 16));
}


void TTDNavigationWidget::showAllAccesses()
{
	if (!m_controller || !m_controller->IsConnected() || !m_controller->IsTTD())
	{
		setStatus("TTD is not available.");
		return;
	}

	TTDMemoryAccessType accessType = getSelectedAccessTypes();
	if (accessType == 0)
	{
		setStatus("Select at least one of R/W/X.");
		return;
	}

	uint64_t address = 0;
	uint64_t size = 0;
	if (!parseMemoryTarget(address, size))
		return;

	UIContext* context = UIContext::contextForWidget(this);
	if (!context)
		return;

	auto* globalUI = GlobalDebuggerUI::GetForContext(context);
	if (!globalUI)
		return;

	// QueryTTDMemoryAccess only reads the context and the binary view off the action context,
	// so there is no code view selection to stand in for here.
	UIActionContext ctxt;
	ctxt.context = context;
	ctxt.binaryView = m_data;

	setStatus(QString());
	globalUI->QueryTTDMemoryAccess(
		ctxt, address, address + size, static_cast<BNDebuggerTTDMemoryAccessType>(accessType));
}


void TTDNavigationWidget::goToPrev()
{
	navigate(false);
}


void TTDNavigationWidget::goToNext()
{
	navigate(true);
}
