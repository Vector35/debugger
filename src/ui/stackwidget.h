#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtCore/QItemSelectionModel>
#include <QtCore/QModelIndex>
#include <QtWidgets/QTableView>
#include <QtWidgets/QStyledItemDelegate>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "theme.h"
#include "../debuggerstate.h"

enum DebugStackValueStatus
{
    DebugStackValueNormal,
    // The current value is different from the last value
    DebugStackValueChanged,
    // The value has been modified by the user
    DebugStackValueModified
};


class DebugStackItem
{
private:
    ssize_t m_offset;
    uint64_t m_address;
    uint64_t m_value;
    // TODO: add references later
    DebugStackValueStatus m_valueStatus;

public:
    DebugStackItem(ssize_t offset, uint64_t address, uint64_t value,
        DebugStackValueStatus valueStatus = DebugStackValueNormal);
    ssize_t offset() const { return m_offset; }
    uint64_t address() const { return m_address; }
    uint64_t value() const { return m_value; }
    void setValue(uint64_t value) { m_value = value; }
    DebugStackValueStatus valueStatus() const { return m_valueStatus; }
    void setValueStatus(DebugStackValueStatus newStatus) { m_valueStatus = newStatus; }
    bool operator==(const DebugStackItem& other) const;
    bool operator!=(const DebugStackItem& other) const;
    bool operator<(const DebugStackItem& other) const;
};

Q_DECLARE_METATYPE(DebugStackItem);


class BINARYNINJAUIAPI DebugStackListModel: public QAbstractTableModel
{
    Q_OBJECT

protected:
    QWidget* m_owner;
    BinaryViewRef m_data;
    ViewFrame* m_view;
    std::vector<DebugStackItem> m_items;

public:
    enum ColumnHeaders
    {
        OffsetColumn,
        AddressColumn,
        ValueColumn,
    };

    DebugStackListModel(QWidget* parent, BinaryViewRef data, ViewFrame* view);
    virtual ~DebugStackListModel();

    virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;
    virtual Qt::ItemFlags flags(const QModelIndex &index) const override;

    virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override
        { (void) parent; return (int)m_items.size(); }
    virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override { (void) parent; return 3; }
    DebugStackItem getRow(int row) const;
    virtual QVariant data(const QModelIndex& i, int role) const override;
    virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
    void updateRows(std::vector<DebugStackItem> newRows);
    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole) override;
};


class BINARYNINJAUIAPI DebugStackItemDelegate: public QStyledItemDelegate
{
    Q_OBJECT

    QFont m_font;
    int m_baseline, m_charWidth, m_charHeight, m_charOffset;

public:
    DebugStackItemDelegate(QWidget* parent);
    void updateFonts();
    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
    QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const;
};


class BINARYNINJAUIAPI DebugStackWidget: public QWidget, public DockContextHandler
{
    Q_OBJECT
    Q_INTERFACES(DockContextHandler)

    ViewFrame* m_view;
    BinaryViewRef m_data;

    UIActionHandler* M_actionHandler;
    QTableView* m_table;
    DebugStackListModel* m_model;
    DebugStackItemDelegate* m_delegate;

    // void shouldBeVisible()

    virtual void notifyFontChanged() override;


public:
    DebugStackWidget(ViewFrame* view, const QString& name, BinaryViewRef data);
    void notifyStackChanged(std::vector<DebugStackItem> stackItems);
};

