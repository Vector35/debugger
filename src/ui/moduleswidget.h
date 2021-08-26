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


class DebugModulesListModel: public QAbstractTableModel
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


class DebugModulesItemDelegate: public QStyledItemDelegate
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


class DebugModulesWidget: public SidebarWidget
{
    Q_OBJECT

    ViewFrame* m_view;
    BinaryViewRef m_data;
    DebuggerState* m_state;

    UIActionHandler* M_actionHandler;
    QTableView* m_table;
    DebugModulesListModel* m_model;
    DebugModulesItemDelegate* m_delegate;

    // void shouldBeVisible()
    virtual void notifyFontChanged() override;


public:
    DebugModulesWidget(const QString& name, ViewFrame* view, BinaryViewRef data);

    void notifyModulesChanged(std::vector<DebugModule> modules);

public slots:
    void updateContent();
};


class DebugModulesWidgetType : public SidebarWidgetType {
public:
    DebugModulesWidgetType(const QImage& icon, const QString& name) : SidebarWidgetType(icon, name) { }

    bool isInReferenceArea() const override { return false; }

    SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override {
        return new DebugModulesWidget("Native Debugger Modules", frame, data);
    }
};
