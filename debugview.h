#pragma once

// #include <QtWidgets/QScrollArea>
#include <QtWidgets/QPushButton>
#include "viewframe.h"
#include "dockwidgets/controlswidget.h"
#include "debuggerstate.h"
#include "linearview.h"
#include "disassemblyview.h"
#include <QtWidgets/QSplitter>
// #include "byte.h"


class DebugView: public QWidget, public View
{
    Q_OBJECT

	BinaryViewRef m_data;
	uint64_t m_currentOffset = 0;
	// ByteView* m_byteView = nullptr;
	// QPushButton* m_fullAnalysisButton = nullptr;
    bool m_isRawDisassembly = false;

    DebuggerState* m_state;
    DebugControlsWidget* m_controls;

    QSplitter* m_splitter;

    LinearView* m_memoryEditor;
    DisassemblyContainer* m_binaryEditor;

public:
	DebugView(QWidget* parent, BinaryViewRef data);
    virtual ~DebugView() {}

	virtual BinaryViewRef getData() override;
	virtual uint64_t getCurrentOffset() override;
	virtual BNAddressRange getSelectionOffsets() override;
	virtual void setSelectionOffsets(BNAddressRange range) override;
	virtual QFont getFont() override;
	virtual bool navigate(uint64_t addr) override;

	void setCurrentOffset(uint64_t offset);
	// void navigateToFileOffset(uint64_t offset);

protected:
	virtual void focusInEvent(QFocusEvent* event) override;

private Q_SLOTS:
	// void startFullAnalysis();
};


class DebugViewType: public ViewType
{
public:
	DebugViewType();
	virtual int getPriority(BinaryViewRef data, const QString& filename) override;
	virtual QWidget* create(BinaryViewRef data, ViewFrame* frame) override;
};
