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

#include "attachprocess.h"


using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;

AttachProcessDialog::AttachProcessDialog(QWidget* parent, DebuggerControllerRef controller) :
	QDialog(), m_controller(controller)
{
	setWindowTitle("Attach to process");
	setMinimumSize(UIContext::getScaledWindowSize(350, 600));
	setAttribute(Qt::WA_DeleteOnClose);
	setSizeGripEnabled(true);

	setModal(true);
	QVBoxLayout* layout = new QVBoxLayout;
	layout->setSpacing(0);

	m_processTable = new QTableWidget(this);

	auto processList = controller->GetProcessList();

	m_processTable->setColumnCount(2);
	m_processTable->setRowCount(processList.size());

	QStringList headers;
	headers << "PID"
			<< "Name";

	m_processTable->setHorizontalHeaderLabels(headers);
	m_processTable->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);

	m_processTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
	m_processTable->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);

	m_processTable->verticalHeader()->setVisible(false);

	m_processTable->setShowGrid(false);
	m_processTable->setAlternatingRowColors(true);

	m_processTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_processTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_processTable->setSelectionMode(QAbstractItemView::SingleSelection);

	for (int i = 0; i < processList.size(); i++)
	{
		auto process = processList.at(i);
		m_processTable->setItem(i, 0, new QTableWidgetItem(QString::number(process.m_pid)));
		m_processTable->setItem(i, 1, new QTableWidgetItem(process.m_processName.c_str()));
	}

	m_processTable->resizeColumnsToContents();

	QFormLayout* formLayout = new QFormLayout;
	formLayout->addRow(m_processTable);

	QHBoxLayout* buttonLayout = new QHBoxLayout;
	buttonLayout->setContentsMargins(0, 0, 0, 0);

	QPushButton* cancelButton = new QPushButton("Cancel");
	connect(cancelButton, &QPushButton::clicked, [&]() { reject(); });

	QPushButton* acceptButton = new QPushButton("Attach");
	connect(acceptButton, &QPushButton::clicked, [&]() { apply(); });
	acceptButton->setDefault(true);

	buttonLayout->addStretch(1);
	buttonLayout->addWidget(cancelButton);
	buttonLayout->addWidget(acceptButton);

	layout->addLayout(formLayout);
	layout->addSpacing(10);
	layout->addLayout(buttonLayout);

	setLayout(layout);
}

uint32_t AttachProcessDialog::GetSelectedPid()
{
	return m_pid;
}

void AttachProcessDialog::apply()
{
	if (!m_processTable->selectionModel()->hasSelection())
	{
		reject();
		return;
	}

	QModelIndexList sel = m_processTable->selectionModel()->selectedIndexes();
	if (sel.empty() || !sel[0].isValid())
	{
		reject();
		return;
	}

	QTableWidgetItem* processSelected = m_processTable->item(sel[0].row(), 0);
	m_pid = processSelected->text().toInt();

	accept();
}
