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

#pragma once

#include <QWidget>
#include <QLineEdit>
#include <QLabel>
#include <QCheckBox>
#include <QToolButton>
#include <set>
#include <string>
#include "binaryninjaapi.h"
#include "uicontext.h"
#include "viewframe.h"
#include "debuggerapi.h"

using namespace BinaryNinjaDebuggerAPI;


// A compact always-available version of the "TTD Memory Access (Next/Prev)" dialog and the
// "Go to Next/Previous Register Write" context menu items. It tracks whatever the user has
// selected in the code view -- a register token, or an address range -- and lets them walk
// the trace backwards/forwards from there. It only makes sense during a TTD session, so the
// whole widget is hidden otherwise.
class TTDNavigationWidget : public QWidget, public UIContextNotification
{
	Q_OBJECT

	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;

	QLineEdit* m_targetEdit;
	QCheckBox* m_pinCheck;
	QCheckBox* m_readAccessCheck;
	QCheckBox* m_writeAccessCheck;
	QCheckBox* m_executeAccessCheck;
	QToolButton* m_showAllButton;
	QToolButton* m_prevButton;
	QToolButton* m_nextButton;
	QLabel* m_statusLabel;

	// True when the target field holds a register name rather than an address range. Kept in
	// sync with the field itself: refreshed both when we auto-fill it and when the user types.
	bool m_targetIsRegister = false;

	// The register names of the view's architecture, lower-cased. Used to tell a hand-typed
	// register name (including sub-registers like "eax") from an address expression.
	std::set<std::string> m_registerNames;
	ArchitectureRef m_registerNamesArch;

	void updateRegisterNames();
	bool isRegisterName(const std::string& text);
	void setTargetIsRegister(bool isRegister);

	void updateNavigationButtons();
	// Sets the status line, hiding it entirely while there is nothing to report so that it does
	// not sit there as an empty row between the widget and the tabs below it.
	void setStatus(const QString& text);
	TTDMemoryAccessType getSelectedAccessTypes();
	void navigate(bool forward);
	void navigateToRegisterWrite(const std::string& reg, bool forward);
	void navigateToMemoryAccess(bool forward);
	bool parseMemoryTarget(uint64_t& address, uint64_t& size);

public:
	TTDNavigationWidget(QWidget* parent, BinaryViewRef data);
	~TTDNavigationWidget();

	// Show/hide the widget based on whether a TTD session is active, and enable/disable the
	// navigation buttons based on whether the target is currently stopped.
	void updateState();

	// Pick up the token/selection the user is on.
	void updateTargetFromView(View* view);

	// Clicking a different token on the instruction the cursor is already on does not move the
	// current offset, and Sidebar::updateViewLocation drops the view location notification when
	// the location compares equal -- ViewLocation carries no token. The cross reference
	// selection notification is not filtered that way, so it is what catches register tokens.
	void OnNewSelectionForXref(
		UIContext* context, ViewFrame* frame, View* view, const SelectionInfoForXref& selection) override;

private Q_SLOTS:
	// Same as updateTargetFromView(), against whichever view the context currently has open.
	void refreshTargetFromSelection();
	void pinToggled(bool pinned);
	void targetEdited(const QString& text);
	void goToPrev();
	void goToNext();
	// Hand the target off to the TTD Memory sidebar widget, exactly as the "TTD Memory Access"
	// context menu items do, to list every access rather than stepping to one.
	void showAllAccesses();
};
