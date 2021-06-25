#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtCore/QItemSelectionModel>
#include <QtCore/QModelIndex>
#include <QtWidgets/QTableView>
#include <QtWidgets/QStyledItemDelegate>
#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "viewframe.h"
#include "debuggerstate.h"

class DebugRegisterItem
{
private:
    string m_name;
    uint64_t m_value;
    bool m_updated;
    // TODO: We probably need a more robust mechenism for this
    string m_hint;

public:
    DebugRegisterItem(const string& name, uint64_t value, bool updated = false, const string& hint = "");
    string name() const { return m_name; }
    uint64_t value() const { return m_value; }
    bool updated() const { return m_updated; }
    string hint() const { return m_hint; }
    bool operator==(const DebugRegisterItem& other) const;
    bool operator!=(const DebugRegisterItem& other) const;
    bool operator<(const DebugRegisterItem& other) const;
};

Q_DECLARE_METATYPE(DebugRegisterItem);


class BINARYNINJAUIAPI DebugRegisterListModel: public QAbstractTableModel
{
    Q_OBJECT

protected:
    QWidget* m_owner;
    BinaryViewRef m_data;
    ViewFrame* m_view;
    std::vector<DebugRegister> m_items;

public:
    enum ColumnHeaders
    {
        NameColumn
        ValueColumn,
        HintColumn,
    };

    DebugRegisterListModel(QWidget* parent, BinaryViewRef data, ViewFrame* view);
    virtual ~DebugRegisterListModel();

    virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;
    virtual Qt::ItemFlags flags(const QModelIndex &index) const override;

    virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override { (void) parent; return (int)m_refs.size(); }
    virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override { (void) parent; return 3; }
    DebugRegister getRow(int row) const;
    virtual QVariant data(const QModelIndex& i, int role) const override;
    virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
    void updateRows(std::vector<DebugRegister> newRows);
};


class BINARYNINJAUIAPI DebugRegisterItemDelegate: public QStyledItemDelegate
{
    Q_OBJECT

    QFont m_font;
    int m_baseline, m_charWidth, m_charHeight, m_charOffset;

public:
    DebugRegisterItemDelegate(QWidget* parent);
    void updateFonts();
    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
};


class BINARYNINJAUIAPI DebugRegisterWidget: public QWidget, public DockContextHandler
{
    Q_OBJECT
    Q_INTERFACES(DockContextHandler)

    ViewFrame* m_view;
    BinaryViewRef m_data;

    UIActionHandler* M_actionHandler;
    QTableView* m_table;
    DebugRegisterListModel* m_model;
    DebugRegisterItemDelegate* m_delegate;

    void notifyRegistersChanges(std::vector<DebugRegister>);
    // void shouldBeViaible()




public:
    DebugRegisterWidget(ViewFrame* view, const std::string& name, BinaryViewRef data);
};
