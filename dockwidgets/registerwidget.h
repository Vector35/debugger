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
    DebugRegisterItem(const string& name, uint64_t value, bool updated = false, const string& hint);
    string name() const { return m_name; }
    uint64_t value() const { return m_value; }
    bool updated() const { return m_updated; }
    string hint() const { return m_hint; }
    bool operator==(const DebugRegisterItem& other) const
};

Q_DECLARE_METATYPE(DebugRegisterItem);


class BINARYNINJAUIAPI DebugRegisterListModel: public QAbstractTableModel
{
    Q_OBJECT

protected:
    QWidget* m_owner;
    BinaryViewRef m_data;
    std::vector<DebugRegister> m_items;

public:

};


class BINARYNINJAUIAPI DebugRegisterWidget: public QWidget, public DockContextHandler
{
    Q_OBJECT
    Q_INTERFACES(DockContextHandler)

    ViewFrame* m_view;
    BinaryViewRef m_data;

    UIActionHandler* M_actionHandler;
    QTableView* m_table;




public:
    DebugRegisterWidget(ViewFrame* view, const std::string& name, BinaryViewRef data);
};
