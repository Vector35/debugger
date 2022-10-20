/*
Copyright 2020-2022 Vector 35 Inc.

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

#include <QPainter>
#include <QHeaderView>
#include <QLineEdit>
#include <QListView>
#include <QGuiApplication>
#include <QMimeData>
#include <QClipboard>
#include "clickablelabel.h"
#include "registerswidget.h"

using namespace BinaryNinja;
using namespace std;

constexpr int SortFilterRole = Qt::UserRole + 1;

DebugRegisterItem::DebugRegisterItem(const string& name, uint64_t value, DebugRegisterValueStatus valueStatus,
    const string& hint, bool used):
    m_name(name), m_value(value), m_valueStatus(valueStatus), m_hint(hint), m_used(used)
{
}


bool DebugRegisterItem::operator==(const DebugRegisterItem& other) const
{
    return (m_name == other.name()) && (m_value == other.value()) && (m_valueStatus == other.valueStatus()) &&
        (m_hint == other.hint() && (m_used == other.used()));
}


bool DebugRegisterItem::operator!=(const DebugRegisterItem& other) const
{
    return !(*this == other);
}


bool DebugRegisterItem::operator<(const DebugRegisterItem& other) const
{
    if (m_name < other.name())
        return true;
    else if (m_name > other.name())
        return false;
    else if (m_value < other.value())
        return true;
    else if (m_value > other.value())
        return false;
    else if (m_valueStatus < other.valueStatus())
        return true;
    else if (m_valueStatus > other.valueStatus())
        return false;
	else if (m_hint < other.hint())
		return true;
	else if (m_hint > other.hint())
		return false;
    return m_used < other.used();
}


DebugRegistersListModel::DebugRegistersListModel(QWidget* parent, DebuggerControllerRef controller, ViewFrame* view):
    QAbstractTableModel(parent), m_controller(controller), m_view(view)
{   
}


DebugRegistersListModel::~DebugRegistersListModel()
{
}



Qt::ItemFlags DebugRegistersListModel::flags(const QModelIndex &index) const
{
    Qt::ItemFlags flag = QAbstractTableModel::flags(index);
    if (index.column() == DebugRegistersListModel::ValueColumn)
        flag |= Qt::ItemIsEditable;

    return flag;
}


DebugRegisterItem DebugRegistersListModel::getRow(int row) const
{
    if ((size_t)row >= m_items.size())
		throw std::runtime_error("row index out-of-bound");

    return m_items[row];
}


QModelIndex DebugRegistersListModel::index(int row, int column, const QModelIndex &) const
{
	if (row < 0 || (size_t)row >= m_items.size() || column >= columnCount())
	{
		return QModelIndex();
	}

	return createIndex(row, column, (void*)&m_items[row]);
}


QVariant DebugRegistersListModel::data(const QModelIndex& index, int role) const
{
    if (index.column() >= columnCount() || (size_t)index.row() >= m_items.size())
		return QVariant();

	DebugRegisterItem *item = static_cast<DebugRegisterItem*>(index.internalPointer());
	if (!item)
		return QVariant();


    if ((role != Qt::DisplayRole) && (role != Qt::SizeHintRole) && (role != SortFilterRole))
        return QVariant();

    switch (index.column())
    {
    case DebugRegistersListModel::NameColumn:
    {
        if (role == Qt::SizeHintRole)
            return QVariant((qulonglong)item->name().size());

		if (role == SortFilterRole)
			return QVariant(QString::fromStdString(item->name()));

        QList<QVariant> line;
        line.push_back(getThemeColor(RegisterColor).rgba());
		line.push_back(QString::fromStdString(item->name()));
		return QVariant(line);
    }
    case DebugRegistersListModel::ValueColumn:
    {
        // TODO: We need better alignment for values
        uint64_t value = item->value();
        QString valueStr = QString::asprintf("0x%" PRIx64, value);
        if (role == Qt::SizeHintRole)
            return QVariant((qulonglong)valueStr.size());

		if (role == SortFilterRole)
			return QVariant(valueStr);

        QList<QVariant> line;
        switch (item->valueStatus())
        {
        case DebugRegisterValueNormal:
            line.push_back(getThemeColor(AddressColor).rgba());
            break;
        case DebugRegisterValueChanged:
            line.push_back(getThemeColor(RedStandardHighlightColor).rgba());
            break;
        case DebugRegisterValueModified:
            line.push_back(getThemeColor(RedStandardHighlightColor).rgba());
            break;
        }

		line.push_back(valueStr);
		return QVariant(line);
    }
    case DebugRegistersListModel::HintColumn:
    {
        if (role == Qt::SizeHintRole)
            return QVariant((qulonglong)item->hint().size());

		if (role == SortFilterRole)
			return QVariant(QString::fromStdString(item->hint()));

        QList<QVariant> line;
        line.push_back(getThemeColor(StringColor).rgba());
		line.push_back(QString::fromStdString(item->hint()));
		return QVariant(line);
    }
    }
    return QVariant();
}


QVariant DebugRegistersListModel::headerData(int column, Qt::Orientation orientation, int role) const
{
	if (role != Qt::DisplayRole)
		return QVariant();

	if (orientation == Qt::Vertical)
		return QVariant();

	switch (column)
	{
		case DebugRegistersListModel::NameColumn:
			return "Name";
		case DebugRegistersListModel::ValueColumn:
			return "Value";
		case DebugRegistersListModel::HintColumn:
			return "Hint";
	}
	return QVariant();
}


std::set<std::string> DebugRegistersListModel::getUsedRegisterNames()
{
	std::set<std::string> usedRegisterNames;
	if (!m_controller->GetLiveView())
		return usedRegisterNames;

	auto pc = m_controller->IP();
	auto arch = m_controller->GetLiveView()->GetDefaultArchitecture();
	if (!arch)
		return usedRegisterNames;

	auto functions = m_controller->GetLiveView()->GetAnalysisFunctionsContainingAddress(pc);
	if (functions.empty() || (!functions[0]))
		return usedRegisterNames;

	auto llil = functions[0]->GetLowLevelIL();
	if (!llil)
		return usedRegisterNames;

	auto regs = llil->GetRegisters();
	for (const auto reg: regs)
	{
		const auto name = arch->GetRegisterName(reg);
		usedRegisterNames.insert(name);
	}

	return usedRegisterNames;
}


void DebugRegistersListModel::updateRows(std::vector<DebugRegister> newRows)
{
	const auto usedRegisterNames = getUsedRegisterNames();
	bool emptyUsedRegisters = usedRegisterNames.size() == 0;

    // TODO: This might cause performance problems. We can instead only update the chained registers.
    // However, the cost for that is we need to attach an index to each item and sort accordingly
    beginResetModel();
    std::map<std::string, uint64_t> oldRegValues;
    for (const DebugRegisterItem& item: m_items)
        oldRegValues[item.name()] = item.value();

    m_items.clear();
    if (newRows.size() == 0)
    {
        endResetModel();
        return;
    }

    for (const DebugRegister& reg: newRows)
    {
        auto iter = oldRegValues.find(reg.m_name);
        DebugRegisterValueStatus status;
        if (iter == oldRegValues.end())
        {
            status = DebugRegisterValueNormal;
        }
        else
        {
            if (iter->second == reg.m_value)
            {
                status = DebugRegisterValueNormal;
            }
            else
            {
                status = DebugRegisterValueChanged;
            }
        }

		// If we get an empty list of used registers, we wish to show all regs
		bool used = (emptyUsedRegisters || (usedRegisterNames.find(reg.m_name) != usedRegisterNames.end()));
        m_items.emplace_back(reg.m_name, reg.m_value, status, reg.m_hint, used);
    }
    endResetModel();
}


bool DebugRegistersListModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if ((flags(index) & Qt::ItemIsEditable) != Qt::ItemIsEditable)
        return false;

    QString valueStr = value.toString();
    if (valueStr.size() == 0)
        return false;

    if (index.column() >= columnCount() || (size_t)index.row() >= m_items.size())
		return false;

	DebugRegisterItem *item = static_cast<DebugRegisterItem*>(index.internalPointer());
	if (!item)
        return false;

	uint64_t currentValue = item->value();

	uint64_t newValue = 0;
	std::string errorString;
	if (!BinaryView::ParseExpression(m_controller->GetLiveView(), valueStr.toStdString(), newValue, currentValue, errorString))
		return false;

    if (newValue == currentValue)
        return false;

    if (!m_controller->SetRegisterValue(item->name(), newValue))
        return false;

	emit dataChanged(index, index);
    return true;
}


DebugRegistersItemDelegate::DebugRegistersItemDelegate(QWidget* parent):
    QStyledItemDelegate(parent)
{
    updateFonts();
}


void DebugRegistersItemDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option,
	const QModelIndex& idx) const
{
	painter->setFont(m_font);

	bool selected = (option.state & QStyle::State_Selected) != 0;
	if (selected)
		painter->setBrush(getThemeColor(SelectionColor));
	else
		painter->setBrush(option.backgroundBrush);

	painter->setPen(Qt::NoPen);

	QRect textRect = option.rect;
	textRect.setBottom(textRect.top() + m_charHeight + 2);
	painter->drawRect(textRect);

	auto data = idx.data(Qt::DisplayRole);
	switch (idx.column())
	{
	case DebugRegistersListModel::NameColumn:
	case DebugRegistersListModel::ValueColumn:
	case DebugRegistersListModel::HintColumn:
	{
		auto tokenPair = data.toList();
		if (tokenPair.size() == 0)
			break;
		painter->setPen(QColor((QRgb)tokenPair[0].toInt()));
		painter->drawText(textRect, tokenPair[1].toString());
		break;
	}
	default:
		break;
	}
}


void DebugRegistersItemDelegate::updateFonts()
{
	// Get font and compute character sizes
	m_font = getMonospaceFont(dynamic_cast<QWidget*>(parent()));
	m_font.setKerning(false);
	m_baseline = (int)QFontMetricsF(m_font).ascent();
	m_charWidth = getFontWidthAndAdjustSpacing(m_font);
	m_charHeight = (int)(QFontMetricsF(m_font).height() + getExtraFontSpacing());
	m_charOffset = getFontVerticalOffset();
}


QSize DebugRegistersItemDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const
{
    auto totalWidth = (idx.data(Qt::SizeHintRole).toInt() + 2) * m_charWidth + 4;
    return QSize(totalWidth, m_charHeight + 2);
}


void DebugRegistersItemDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    if (index.column() == DebugRegistersListModel::ValueColumn)
    {
        QLineEdit* lineEditor = static_cast<QLineEdit*>(editor);
        if (lineEditor)
        {
            // index.data() returns a pair of color and QString
            lineEditor->setText(index.data().toList()[1].toString());
        }
    }
}


DebugRegistersWidget::DebugRegistersWidget(ViewFrame* view, BinaryViewRef data, Menu* menu):
    m_view(view)
{
    m_controller = DebuggerController::GetController(data);

    m_table = new QTableView(this);
    m_model = new DebugRegistersListModel(m_table, m_controller, view);
	m_filter = new DebugRegisterFilterProxyModel(this);
	m_filter->setSourceModel(m_model);
	m_table->setModel(m_filter);
	m_table->setEditTriggers(QAbstractItemView::EditKeyPressed);
	m_table->setShowGrid(false);

    m_delegate = new DebugRegistersItemDelegate(this);
    m_table->setItemDelegate(m_delegate);

    m_table->setSelectionBehavior(QAbstractItemView::SelectItems);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);

    m_table->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_table->verticalHeader()->setVisible(false);

	m_table->horizontalHeader()->setStretchLastSection(true);
	m_table->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_table->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_table->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);

    m_table->resizeColumnsToContents();
    m_table->resizeRowsToContents();

    QVBoxLayout* layout = new QVBoxLayout;
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    layout->addWidget(m_table);
    setLayout(layout);

	m_actionHandler.setupActionHandler(this);
	m_contextMenuManager = new ContextMenuManager(this);
	m_menu = menu;
	if (m_menu == nullptr)
		m_menu = new Menu();

	QString actionName = QString::fromStdString("Set To Zero");
	UIAction::registerAction(actionName);
	m_menu->addAction(actionName, "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction(actionName, UIAction([=](){ setToZero(); }));

	actionName = QString::fromStdString("Edit Value");
	UIAction::registerAction(actionName, QKeySequence(Qt::Key_Enter));
	m_menu->addAction(actionName, "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction(actionName, UIAction([=](){ editValue(); }));

	actionName = QString::fromStdString("Jump To Address");
	UIAction::registerAction(actionName);
	m_menu->addAction(actionName, "Options", MENU_ORDER_FIRST);
	m_actionHandler.bindAction(actionName, UIAction([=](){ jump(); }));

	m_menu->addAction("Copy", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Copy", UIAction([&](){ copy(); }, [&](){ return canCopy(); }));
	m_actionHandler.setActionDisplayName("Copy", [&](){
		QModelIndexList sel = m_table->selectionModel()->selectedIndexes();
		if (sel.empty())
			return "Copy";

		switch (sel[0].column())
		{
		case DebugRegistersListModel::NameColumn:
			return "Copy Name";
		case DebugRegistersListModel::ValueColumn:
			return "Copy Value";
		case DebugRegistersListModel::HintColumn:
			return "Copy Hint";
		default:
			return "Copy";
		}
	});

	m_menu->addAction("Paste", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Paste", UIAction([&](){ paste(); }, [&](){ return canPaste(); }));

	actionName = QString::fromStdString("Hide Unused Registers");
	UIAction::registerAction(actionName);
	m_menu->addAction(actionName, "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction(actionName, UIAction([=](){
		m_filter->toggleHideUnusedRegisters();
	}));
	m_actionHandler.setChecked(actionName, [this]() { return m_filter->getHideUnusedRegisters();});

	connect(m_model, &DebugRegistersListModel::dataChanged, [&](){
		updateContent();
	});

	connect(m_table, &QTableView::doubleClicked, this, &DebugRegistersWidget::onDoubleClicked);

    updateContent();
}


void DebugRegistersWidget::notifyRegistersChanged(std::vector<DebugRegister> regs)
{
    m_model->updateRows(regs);
	m_table->resizeColumnToContents(DebugRegistersListModel::NameColumn);
	m_table->resizeColumnToContents(DebugRegistersListModel::ValueColumn);
}


void DebugRegistersWidget::contextMenuEvent(QContextMenuEvent* event)
{
    showContextMenu();
}


void DebugRegistersWidget::showContextMenu()
{
	m_contextMenuManager->show(m_menu, &m_actionHandler);
}


void DebugRegistersWidget::updateContent()
{
    if (!m_controller->IsConnected())
        return;

    std::vector<DebugRegister> registers = m_controller->GetRegisters();
    notifyRegistersChanged(registers);
}


void DebugRegistersWidget::setToZero()
{
	QModelIndexList sel = m_table->selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	auto sourceIndex = m_filter->mapToSource(sel[0]);
	if (!sourceIndex.isValid())
		return;

	auto reg = m_model->getRow(sourceIndex.row());
	m_controller->SetRegisterValue(reg.name(), 0);

	updateContent();
}


void DebugRegistersWidget::jump()
{
	QModelIndexList sel = m_table->selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	auto sourceIndex = m_filter->mapToSource(sel[0]);
	if (!sourceIndex.isValid())
		return;

	auto reg = m_model->getRow(sourceIndex.row());
	uint64_t value = reg.value();

	UIContext* context = UIContext::contextForWidget(this);
	if (!context)
		return;

	ViewFrame* frame = context->getCurrentViewFrame();
	if (!frame)
		return;

	if (m_controller->GetLiveView())
		frame->navigate(m_controller->GetLiveView(), value, true, true);
	else
		frame->navigate(m_controller->GetData(), value, true, true);
}


void DebugRegistersWidget::copy()
{
	QModelIndexList sel = m_table->selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	auto sourceIndex = m_filter->mapToSource(sel[0]);
	if (!sourceIndex.isValid())
		return;

	auto reg = m_model->getRow(sourceIndex.row());
	QString text;

	switch (sel[0].column())
	{
	case DebugRegistersListModel::NameColumn:
		text = QString::fromStdString(reg.name());
		break;
	case DebugRegistersListModel::ValueColumn:
		text = QString::asprintf("0x%" PRIx64, reg.value());
		break;
	case DebugRegistersListModel::HintColumn:
		text = QString::fromStdString(reg.hint());
		break;
	default:
		break;
	}

	auto* clipboard = QGuiApplication::clipboard();
	clipboard->clear();
	auto* mime = new QMimeData();
	mime->setText(text);
	clipboard->setMimeData(mime);
}


void DebugRegistersWidget::paste()
{
	QModelIndexList sel = m_table->selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	if (sel[0].column() != DebugRegistersListModel::ValueColumn)
		return;

	auto sourceIndex = m_filter->mapToSource(sel[0]);
	if (!sourceIndex.isValid())
		return;

	auto reg = m_model->getRow(sourceIndex.row());

	QClipboard* clipboard = QGuiApplication::clipboard();
	auto text = clipboard->text();

	uint64_t newValue = 0;
	std::string errorString;
	if (!BinaryView::ParseExpression(m_controller->GetLiveView(), text.toStdString(), newValue, reg.value(), errorString))
		return;

	if (newValue == reg.value())
		return;

	if (!m_controller->SetRegisterValue(reg.name(), newValue))
		return;

	updateContent();
}


bool DebugRegistersWidget::canCopy()
{
	QModelIndexList sel = m_table->selectionModel()->selectedIndexes();
	return !sel.empty();
}


bool DebugRegistersWidget::canPaste()
{
	QModelIndexList sel = m_table->selectionModel()->selectedIndexes();
	if (sel.empty())
		return false;

	return sel[0].column() == DebugRegistersListModel::ValueColumn;
}


void DebugRegistersWidget::onDoubleClicked()
{
	jump();
}


void DebugRegistersWidget::editValue()
{
	QModelIndexList sel = m_table->selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	if (sel[0].column() != DebugRegistersListModel::ValueColumn)
		return;

	auto sourceIndex = m_filter->mapToSource(sel[0]);
	if (!sourceIndex.isValid())
		return;

	m_table->edit(sourceIndex);
}


void DebugRegistersWidget::setFilter(const string & filter)
{
	m_filter->setFilterRegularExpression(QString::fromStdString(filter));
}


void DebugRegistersWidget::scrollToFirstItem()
{

}


void DebugRegistersWidget::scrollToCurrentItem()
{

}


void DebugRegistersWidget::selectFirstItem()
{

}


void DebugRegistersWidget::activateFirstItem()
{

}


DebugRegistersContainer::DebugRegistersContainer(ViewFrame* view, BinaryViewRef data, Menu* menu): m_view(view)
{
	m_register = new DebugRegistersWidget(view, data, menu);
	m_separateEdit = new FilterEdit(m_register);
	m_filter = new FilteredView(this, m_register, m_register, m_separateEdit);
	m_filter->setFilterPlaceholderText("Search registers");

	auto headerLayout = new QHBoxLayout;
	headerLayout->setContentsMargins(0, 0, 0, 0);
	headerLayout->addWidget(m_separateEdit, 1);

	ClickableIcon* icon = new ClickableIcon(QImage(":/icons/images/menu.png"), QSize(16, 16));
	connect(icon, &ClickableIcon::clicked, m_register, &DebugRegistersWidget::showContextMenu);
	headerLayout->addWidget(icon);

	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0 ,0);
	layout->addLayout(headerLayout);
	layout->addWidget(m_filter, 1);
}


void DebugRegistersContainer::updateContent()
{
	m_register->updateContent();
}

// TODO: Group this with other settings key constants if more pop up.
constexpr auto HideUnusedRegistersKey = "ui/debugger/registers/hideUnused";

DebugRegisterFilterProxyModel::DebugRegisterFilterProxyModel(QObject *parent): QSortFilterProxyModel(parent)
{
	setFilterCaseSensitivity(Qt::CaseInsensitive);

	QSettings settings;
	auto hideUnused = settings.value(HideUnusedRegistersKey);
	if (!hideUnused.isNull())
		m_hideUnusedRegisters = hideUnused.toBool();
}


bool DebugRegisterFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
	QRegularExpression regExp = filterRegularExpression();
	if (!regExp.isValid())
		return true;

	QModelIndex index = sourceModel()->index(sourceRow, 0, sourceParent);
	DebugRegisterItem* item = static_cast<DebugRegisterItem*>(index.internalPointer());
	if (m_hideUnusedRegisters && !item->used())
		return false;

	for (int column = 0; column < sourceModel()->columnCount(sourceParent); column++)
	{
		QModelIndex index = sourceModel()->index(sourceRow, column, sourceParent);
		QString data = index.data(SortFilterRole).toString();
		if (data.indexOf(regExp) != -1)
			return true;
	}
	return false;
}

void DebugRegisterFilterProxyModel::toggleHideUnusedRegisters()
{
	m_hideUnusedRegisters = !m_hideUnusedRegisters;
	QSettings().setValue(HideUnusedRegistersKey, m_hideUnusedRegisters);

	invalidate();
}
