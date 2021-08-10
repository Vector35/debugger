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


class DebugViewHistoryEntry: public HistoryEntry
{
private:
    uint64_t m_memoryAddr;
    uint64_t m_address;
    ModuleNameAndOffset m_relAddress;
    bool m_isRaw;

public:
    DebugViewHistoryEntry(uint64_t memoryAddr, uint64_t address, bool isRaw):
        m_memoryAddr(memoryAddr), m_address(address), m_isRaw(isRaw)
    {}
    DebugViewHistoryEntry(uint64_t memoryAddr, const ModuleNameAndOffset& relAddr, bool isRaw):
        m_memoryAddr(memoryAddr), m_relAddress(relAddr), m_isRaw(isRaw)
    {}

    uint64_t getMemoryAddr() const { return m_memoryAddr; }
    uint64_t getAddress() const { return m_address; }
    ModuleNameAndOffset getRelAddress() { return m_relAddress; }
    bool getIsRaw() const { return m_isRaw; }
};


class DebugView: public QWidget, public View
{
    Q_OBJECT

	BinaryViewRef m_data;
	uint64_t m_currentOffset = 0;
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

    QVBoxLayout* memoryLayout;
    QWidget* m_memoryWidget;
    QLabel* m_memoryLabel;

    TokenizedTextView* m_binaryText;
    DisassemblyContainer* m_binaryEditor;

    bool m_needsUpdate;
    QTimer* m_updateTimer;

    QTabWidget* m_memoryTabs;
    size_t m_numMemoryTabs = 3;

    QLabel* m_debuggerStatus;

public:
	DebugView(QWidget* parent, BinaryViewRef data);
    virtual ~DebugView() {}

	virtual BinaryViewRef getData() override;
	virtual uint64_t getCurrentOffset() override;
	virtual BNAddressRange getSelectionOffsets() override;
	virtual FunctionRef getCurrentFunction() override;
	virtual BasicBlockRef getCurrentBasicBlock() override;
	virtual ArchitectureRef getCurrentArchitecture() override;
	virtual LowLevelILFunctionRef getCurrentLowLevelILFunction() override;
	virtual MediumLevelILFunctionRef getCurrentMediumLevelILFunction() override;

	virtual void setSelectionOffsets(BNAddressRange range) override;
	virtual QFont getFont() override;

	virtual bool navigateToFunction(FunctionRef func, uint64_t offset) override;
	virtual bool navigate(uint64_t addr) override;

	virtual BinaryNinja::Ref<HistoryEntry> getHistoryEntry() override;
	virtual void navigateToHistoryEntry(BinaryNinja::Ref<HistoryEntry> entry) override;

    bool navigateLive(uint64_t addr);
    bool navigateRaw(uint64_t addr);
    void showRawAssembly(bool raw);
    void loadRawDisassembly(uint64_t startIP);
    void refreshRawDisassembly();

	void setCurrentOffset(uint64_t offset);
	// void navigateToFileOffset(uint64_t offset);

    DebugControlsWidget* getControls() const { return m_controls; }
    DisassemblyContainer* getBinaryEditor() const { return m_binaryEditor; }

    void setDebuggerStatus(const std::string& status);

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
