#pragma once

// #include <QtWidgets/QScrollArea>
#include <QtWidgets/QPushButton>
#include "viewframe.h"
#include "controlswidget.h"
#include "../debuggerstate.h"
#include "linearview.h"
#include "disassemblyview.h"
#include "tokenizedtextview.h"
#include <QtWidgets/QSplitter>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QLabel>
#include <QtCore/QTimer>
// #include "byte.h"


class DebugView: public QWidget, public View
{
    Q_OBJECT

	BinaryViewRef m_data;
	uint64_t m_currentOffset = 0;
	// ByteView* m_byteView = nullptr;
	// QPushButton* m_fullAnalysisButton = nullptr;
    bool m_isRawDisassembly;
    uint64_t m_rawAddress, m_memoryHistoryAddress;

    bool m_isNavigatingHistory;

    DebuggerState* m_state;
    DebugControlsWidget* m_controls;

    QSplitter* m_splitter;

    QVBoxLayout* m_binaryViewLayout;
    QWidget* m_binaryViewWidget;
    QLabel* m_bianryViewLabel;

    QVBoxLayout* m_disassemblyLayout;
    QWidget* m_disassemblyWidget;
    QLabel* m_disassemblyLabel;

    QVBoxLayout* m_memoryLayout;
    QWidget* m_memoryWidget;
    QLabel* m_memoryLabel;

    TokenizedTextView* m_binaryText;
    LinearView* m_memoryEditor;
    DisassemblyContainer* m_binaryEditor;

    bool m_needsUpdate;
    QTimer* m_updateTimer;

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
	void updateTimerEvent();
};


class DebugViewType: public ViewType
{
public:
	DebugViewType();
	virtual int getPriority(BinaryViewRef data, const QString& filename) override;
	virtual QWidget* create(BinaryViewRef data, ViewFrame* frame) override;
};
