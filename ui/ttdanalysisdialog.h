/*
Copyright 2020-2025 Vector 35 Inc.

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

#pragma once

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QComboBox>
#include <QTextEdit>
#include <QProgressBar>
#include <QCheckBox>
#include <QLineEdit>
#include <QFileDialog>
#include <QGroupBox>
#include <QListWidget>
#include <QSplitter>
#include <QTimer>
#include <QThread>
#include <QMutex>
#include "binaryninjaapi.h"
#include "debuggerapi.h"
#include <uitypes.h>

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;

enum class TTDAnalysisType {
	CodeCoverage
	// Future analysis types can be added here
};

enum class TTDAnalysisStatus {
	NotRun,
	Running,
	Completed,
	Failed,
	LoadedFromCache
};

struct TTDAnalysisResult {
	TTDAnalysisType type;
	TTDAnalysisStatus status;
	QString name;
	QString description;
	QString cachePath;
	size_t resultCount;
	QDateTime lastRun;
	QString errorMessage;
};

class TTDAnalysisWorker : public QThread
{
	Q_OBJECT

public:
	TTDAnalysisWorker(DbgRef<DebuggerController> controller, TTDAnalysisType type, QObject* parent = nullptr);
	TTDAnalysisWorker(DbgRef<DebuggerController> controller, TTDAnalysisType type, uint64_t startAddress, uint64_t endAddress, QObject* parent = nullptr);

protected:
	void run() override;

signals:
	void analysisProgress(int percentage, const QString& message);
	void analysisCompleted(bool success, const QString& message, size_t resultCount);

private:
	DbgRef<DebuggerController> m_controller;
	TTDAnalysisType m_analysisType;
	bool m_useRange;
	uint64_t m_startAddress;
	uint64_t m_endAddress;
};

class TTDAnalysisDialog : public QDialog
{
	Q_OBJECT

public:
	TTDAnalysisDialog(BinaryViewRef data, QWidget* parent = nullptr);
	~TTDAnalysisDialog();

private slots:
	void onAnalysisSelectionChanged();
	void onRunAnalysis();
	void onSaveResults();
	void onLoadResults();
	void onClearCache();
	void onAnalysisProgress(int percentage, const QString& message);
	void onAnalysisCompleted(bool success, const QString& message, size_t resultCount);
	void onRefreshStatus();

private:
	void setupUI();
	void updateAnalysisStatus();
	void updateButtonStates();
	void populateAnalysisList();
	QString getDefaultCachePath(TTDAnalysisType type);
	bool saveAnalysisResults(const TTDAnalysisResult& result);
	bool loadAnalysisResults(TTDAnalysisResult& result);

	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;

	// UI components
	QComboBox* m_analysisTypeCombo;
	QListWidget* m_analysisListWidget;
	QTextEdit* m_analysisDetailsText;
	QLabel* m_statusLabel;
	QProgressBar* m_progressBar;
	QPushButton* m_runButton;
	QPushButton* m_saveButton;
	QPushButton* m_loadButton;
	QPushButton* m_clearCacheButton;
	QCheckBox* m_autoCacheCheckBox;
	QLineEdit* m_cachePathEdit;
	QPushButton* m_browseCacheButton;

	// Range controls
	QCheckBox* m_useRangeCheckBox;
	QLineEdit* m_startAddressEdit;
	QLineEdit* m_endAddressEdit;

	// Analysis data
	QList<TTDAnalysisResult> m_analysisResults;
	TTDAnalysisWorker* m_currentWorker;
	QTimer* m_statusTimer;
	QMutex m_resultsMutex;
};