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

class ModuleItem
{
private:
    uint64_t m_address;
    size_t m_size;
    std::string m_name;
    std::string m_path;

public:
    ModuleItem(uint64_t address, size_t size, std::string name, std::string path);
    uint64_t address() const { return m_address; }
    size_t size() const { return m_size; }
    std::string name() const { return m_name; }
    std::string path() const { return m_path; }
    bool operator==(const ModuleItem& other) const;
    bool operator!=(const ModuleItem& other) const;
    bool operator<(const ModuleItem& other) const;
};

Q_DECLARE_METATYPE(ModuleItem);


class BINARYNINJAUIAPI DebugModulesListModel: public QAbstractTableModel
{
    Q_OBJECT

protected:
    QWidget* m_owner;
    BinaryViewRef m_data;
    ViewFrame* m_view;
    std::vector<ModuleItem> m_items;

public:
    enum ColumnHeaders
    {
        AddressColumn,
        SizeColumn,
        NameColumn,
        PathColumn,
    };

    DebugModulesListModel(QWidget* parent, BinaryViewRef data, ViewFrame* view);
    virtual ~DebugModulesListModel();

    virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;

    virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override
        { (void) parent; return (int)m_items.size(); }
    virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override { (void) parent; return 4; }
    ModuleItem getRow(int row) const;
    virtual QVariant data(const QModelIndex& i, int role) const override;
    virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
    void updateRows(std::vector<DebugModule> newModules);
};


class BINARYNINJAUIAPI DebugModulesItemDelegate: public QStyledItemDelegate
{
    Q_OBJECT

    QFont m_font;
    int m_baseline, m_charWidth, m_charHeight, m_charOffset;

public:
    DebugModulesItemDelegate(QWidget* parent);
    void updateFonts();
    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
    QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const;
};


class BINARYNINJAUIAPI DebugModulesWidget: public QWidget, public DockContextHandler
{
    Q_OBJECT
    Q_INTERFACES(DockContextHandler)

    ViewFrame* m_view;
    BinaryViewRef m_data;

    UIActionHandler* M_actionHandler;
    QTableView* m_table;
    DebugModulesListModel* m_model;
    DebugModulesItemDelegate* m_delegate;

    // void shouldBeVisible()
    virtual void notifyFontChanged() override;


public:
    DebugModulesWidget(ViewFrame* view, const QString& name, BinaryViewRef data);

    void notifyModulesChanged(std::vector<DebugModule> modules);
};
