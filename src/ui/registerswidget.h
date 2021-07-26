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

enum DebugRegisterValueStatus
{
    DebugRegisterValueNormal,
    // The current value is different from the last value
    DebugRegisterValueChanged,
    // The value has been modified by the user
    DebugRegisterValueModified
};


class DebugRegisterItem
{
private:
    std::string m_name;
    uint64_t m_value;
    DebugRegisterValueStatus m_valueStatus;
    // TODO: We probably need a more robust mechenism for this
    std::string m_hint;

public:
    DebugRegisterItem(const std::string& name, uint64_t value,
        DebugRegisterValueStatus valueStatus = DebugRegisterValueNormal, const std::string& hint = "");
    std::string name() const { return m_name; }
    uint64_t value() const { return m_value; }
    void setValue(uint64_t value) { m_value = value; }
    DebugRegisterValueStatus valueStatus() const { return m_valueStatus; }
    void setValueStatus(DebugRegisterValueStatus newStatus) { m_valueStatus = newStatus; }
    std::string hint() const { return m_hint; }
    bool operator==(const DebugRegisterItem& other) const;
    bool operator!=(const DebugRegisterItem& other) const;
    bool operator<(const DebugRegisterItem& other) const;
};

Q_DECLARE_METATYPE(DebugRegisterItem);


class BINARYNINJAUIAPI DebugRegistersListModel: public QAbstractTableModel
{
    Q_OBJECT

protected:
    QWidget* m_owner;
    BinaryViewRef m_data;
    ViewFrame* m_view;
    std::vector<DebugRegisterItem> m_items;

public:
    enum ColumnHeaders
    {
        NameColumn,
        ValueColumn,
        HintColumn,
    };

    DebugRegistersListModel(QWidget* parent, BinaryViewRef data, ViewFrame* view);
    virtual ~DebugRegistersListModel();

    virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;
    virtual Qt::ItemFlags flags(const QModelIndex &index) const override;

    virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override
        { (void) parent; return (int)m_items.size(); }
    virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override { (void) parent; return 3; }
    DebugRegisterItem getRow(int row) const;
    virtual QVariant data(const QModelIndex& i, int role) const override;
    virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
    void updateRows(std::vector<DebugRegister> newRows);
    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole) override;
};


class BINARYNINJAUIAPI DebugRegistersItemDelegate: public QStyledItemDelegate
{
    Q_OBJECT

    QFont m_font;
    int m_baseline, m_charWidth, m_charHeight, m_charOffset;

public:
    DebugRegistersItemDelegate(QWidget* parent);
    void updateFonts();
    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
    QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const;
};


class BINARYNINJAUIAPI DebugRegistersWidget: public QWidget, public DockContextHandler
{
    Q_OBJECT
    Q_INTERFACES(DockContextHandler)

    ViewFrame* m_view;
    BinaryViewRef m_data;

    UIActionHandler* M_actionHandler;
    QTableView* m_table;
    DebugRegistersListModel* m_model;
    DebugRegistersItemDelegate* m_delegate;

    // void shouldBeVisible()

    virtual void notifyFontChanged() override;


public:
    DebugRegistersWidget(ViewFrame* view, const QString& name, BinaryViewRef data);
    void notifyRegistersChanged(std::vector<DebugRegister> regs);
};

// TODO: support editing register values
