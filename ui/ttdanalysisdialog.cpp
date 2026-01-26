/*
Copyright 2020-2026 Vector 35 Inc.

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

#include "ttdanalysisdialog.h"
#include "debuggeruicommon.h"
#include <QMessageBox>
#include <QStandardPaths>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QApplication>
#include "uicontext.h"
#include "linearview.h"

TTDAnalysisWorker::TTDAnalysisWorker(DbgRef<DebuggerController> controller, TTDAnalysisType type, QObject* parent)
	: QThread(parent), m_controller(controller), m_analysisType(type), m_useRange(false), m_startAddress(0), m_endAddress(0)
{
}

TTDAnalysisWorker::TTDAnalysisWorker(DbgRef<DebuggerController> controller, TTDAnalysisType type, uint64_t startAddress, uint64_t endAddress, TTDPosition startTime, TTDPosition endTime, QObject* parent)
	: QThread(parent), m_controller(controller), m_analysisType(type), m_useRange(true), m_startAddress(startAddress), m_endAddress(endAddress), m_startTime(startTime), m_endTime(endTime)
{
}

void TTDAnalysisWorker::run()
{
	if (!m_controller)
	{
		emit analysisCompleted(false, "No debugger controller available", 0);
		return;
	}

	if (!m_controller->IsTTD())
	{
		emit analysisCompleted(false, "Current adapter does not support TTD", 0);
		return;
	}

	emit analysisProgress(10, "Starting analysis...");

	bool success = false;
	size_t resultCount = 0;
	QString message;

	switch (m_analysisType)
	{
	case TTDAnalysisType::CodeCoverage:
		emit analysisProgress(30, "Running code coverage analysis...");
		if (m_useRange)
		{
			success = m_controller->RunCodeCoverageAnalysis(m_startAddress, m_endAddress, m_startTime, m_endTime);
			if (success)
			{
				resultCount = m_controller->GetExecutedInstructionCount();
				message = QString("Range-based code coverage analysis completed successfully. Found %1 executed instructions in address range 0x%2 - 0x%3 and time range (%4,%5) - (%6,%7).")
					.arg(resultCount)
					.arg(m_startAddress, 0, 16)
					.arg(m_endAddress, 0, 16)
					.arg(m_startTime.sequence).arg(m_startTime.step)
					.arg(m_endTime.sequence).arg(m_endTime.step);
			}
			else
			{
				message = "Range-based code coverage analysis failed";
			}
		}
		else
		{
			emit analysisCompleted(false, "Code coverage analysis requires an address range", 0);
			return;
		}
		break;

	default:
		message = "Unknown analysis type";
		break;
	}

	emit analysisProgress(100, success ? "Analysis completed" : "Analysis failed");
	emit analysisCompleted(success, message, resultCount);
}

TTDAnalysisDialog::TTDAnalysisDialog(UIContext* context, BinaryViewRef data, QWidget* parent)
	: QDialog(parent), m_context(context), m_data(data), m_currentWorker(nullptr)
{
	m_controller = DebuggerController::GetController(data);

	setWindowTitle("TTD Analysis");
	setMinimumSize(800, 600);
	setAttribute(Qt::WA_DeleteOnClose);

	setupUI();
	populateAnalysisList();

	// Set up status refresh timer
	m_statusTimer = new QTimer(this);
	m_statusTimer->setInterval(1000); // Refresh every second
	connect(m_statusTimer, &QTimer::timeout, this, &TTDAnalysisDialog::onRefreshStatus);
	m_statusTimer->start();

	updateAnalysisStatus();
	updateButtonStates();
}

TTDAnalysisDialog::~TTDAnalysisDialog()
{
	if (m_currentWorker)
	{
		m_currentWorker->terminate();
		m_currentWorker->wait(3000); // Wait up to 3 seconds
		delete m_currentWorker;
	}
}

void TTDAnalysisDialog::setupUI()
{
	QVBoxLayout* mainLayout = new QVBoxLayout(this);

	// Analysis type selection
	QGroupBox* selectionGroup = new QGroupBox("Analysis Type");
	QVBoxLayout* selectionLayout = new QVBoxLayout(selectionGroup);

	m_analysisTypeCombo = new QComboBox();
	m_analysisTypeCombo->addItem("Code Coverage", static_cast<int>(TTDAnalysisType::CodeCoverage));
	// Future analysis types can be added here
	selectionLayout->addWidget(m_analysisTypeCombo);

	connect(m_analysisTypeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
			this, &TTDAnalysisDialog::onAnalysisSelectionChanged);

	mainLayout->addWidget(selectionGroup);

	// Analysis list and details
	QSplitter* contentSplitter = new QSplitter(Qt::Horizontal);

	// Analysis list
	QGroupBox* listGroup = new QGroupBox("Available Analyses");
	QVBoxLayout* listLayout = new QVBoxLayout(listGroup);

	m_analysisListWidget = new QListWidget();
	listLayout->addWidget(m_analysisListWidget);

	contentSplitter->addWidget(listGroup);

	// Analysis details
	QGroupBox* detailsGroup = new QGroupBox("Analysis Details");
	QVBoxLayout* detailsLayout = new QVBoxLayout(detailsGroup);

	m_analysisDetailsText = new QTextEdit();
	m_analysisDetailsText->setReadOnly(true);
	detailsLayout->addWidget(m_analysisDetailsText);

	contentSplitter->addWidget(detailsGroup);
	contentSplitter->setSizes({300, 500});

	mainLayout->addWidget(contentSplitter);

	// Status and progress
	QGroupBox* statusGroup = new QGroupBox("Status");
	QVBoxLayout* statusLayout = new QVBoxLayout(statusGroup);

	m_statusLabel = new QLabel("Ready");
	statusLayout->addWidget(m_statusLabel);

	m_progressBar = new QProgressBar();
	m_progressBar->setVisible(false);
	statusLayout->addWidget(m_progressBar);

	mainLayout->addWidget(statusGroup);

	// Range settings
	QGroupBox* rangeGroup = new QGroupBox("Analysis Range (Required)");
	QVBoxLayout* rangeLayout = new QVBoxLayout(rangeGroup);

	m_useRangeCheckBox = new QCheckBox("Specify address range for analysis");
	m_useRangeCheckBox->setChecked(true);
	rangeLayout->addWidget(m_useRangeCheckBox);

	QHBoxLayout* rangeControlsLayout = new QHBoxLayout();
	rangeControlsLayout->addWidget(new QLabel("Start Address:"));
	m_startAddressEdit = new QLineEdit();
	m_startAddressEdit->setText(QString("0x") + QString::number(m_data->GetImageBase(), 16));
	m_startAddressEdit->setEnabled(true);
	rangeControlsLayout->addWidget(m_startAddressEdit);

	rangeControlsLayout->addWidget(new QLabel("End Address:"));
	m_endAddressEdit = new QLineEdit();
	// TODO: hack for demo, should read the modules info from the debugger
	m_endAddressEdit->setText(QString("0x") + QString::number(m_data->GetImageBase() + 0x7000, 16));
	m_endAddressEdit->setEnabled(true);
	rangeControlsLayout->addWidget(m_endAddressEdit);
	rangeLayout->addLayout(rangeControlsLayout);

	// Time settings
	QGroupBox* timeGroup = new QGroupBox("Time Range (Optional)");
	QVBoxLayout* timeLayout = new QVBoxLayout(timeGroup);

	QHBoxLayout* timeControlsLayout = new QHBoxLayout();
	timeControlsLayout->addWidget(new QLabel("Start Time:"));
	m_startTimeEdit = new QLineEdit();
	//set text to starting position
	m_startTimeEdit->setEnabled(true);
	timeControlsLayout->addWidget(m_startTimeEdit);

	timeControlsLayout->addWidget(new QLabel("End Time:"));
	m_endTimeEdit = new QLineEdit();
	//set text to ending position
	m_endTimeEdit->setEnabled(true);
	timeControlsLayout->addWidget(m_endTimeEdit);
	timeLayout->addLayout(timeControlsLayout);

	// Connect range checkbox to enable/disable range controls
	connect(m_useRangeCheckBox, &QCheckBox::toggled, [this](bool checked) {
		m_startAddressEdit->setEnabled(checked);
		m_endAddressEdit->setEnabled(checked);
	});

	mainLayout->addWidget(rangeGroup);
	mainLayout->addWidget(timeGroup);

	// Cache settings
	QGroupBox* cacheGroup = new QGroupBox("Cache Settings");
	QVBoxLayout* cacheLayout = new QVBoxLayout(cacheGroup);

	m_autoCacheCheckBox = new QCheckBox("Automatically cache results");
	m_autoCacheCheckBox->setChecked(true);
	cacheLayout->addWidget(m_autoCacheCheckBox);

	QHBoxLayout* cachePathLayout = new QHBoxLayout();
	cachePathLayout->addWidget(new QLabel("Cache Directory:"));
	m_cachePathEdit = new QLineEdit();
	m_cachePathEdit->setText(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/ttd_analysis");
	cachePathLayout->addWidget(m_cachePathEdit);

	m_browseCacheButton = new QPushButton("Browse...");
	connect(m_browseCacheButton, &QPushButton::clicked, [this]() {
		QString dir = QFileDialog::getExistingDirectory(this, "Select Cache Directory", m_cachePathEdit->text());
		if (!dir.isEmpty())
			m_cachePathEdit->setText(dir);
	});
	cachePathLayout->addWidget(m_browseCacheButton);

	cacheLayout->addLayout(cachePathLayout);
	mainLayout->addWidget(cacheGroup);

	// Buttons
	QHBoxLayout* buttonLayout = new QHBoxLayout();
	buttonLayout->addStretch();

	m_runButton = new QPushButton("Run Analysis");
	connect(m_runButton, &QPushButton::clicked, this, &TTDAnalysisDialog::onRunAnalysis);
	buttonLayout->addWidget(m_runButton);

	m_saveButton = new QPushButton("Save Results");
	connect(m_saveButton, &QPushButton::clicked, this, &TTDAnalysisDialog::onSaveResults);
	buttonLayout->addWidget(m_saveButton);

	m_loadButton = new QPushButton("Load Results");
	connect(m_loadButton, &QPushButton::clicked, this, &TTDAnalysisDialog::onLoadResults);
	buttonLayout->addWidget(m_loadButton);

	m_clearCacheButton = new QPushButton("Clear Cache");
	connect(m_clearCacheButton, &QPushButton::clicked, this, &TTDAnalysisDialog::onClearCache);
	buttonLayout->addWidget(m_clearCacheButton);

	QPushButton* closeButton = new QPushButton("Close");
	connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
	buttonLayout->addWidget(closeButton);

	mainLayout->addLayout(buttonLayout);
}

void TTDAnalysisDialog::populateAnalysisList()
{
	QMutexLocker locker(&m_resultsMutex);

	m_analysisResults.clear();

	// Add Code Coverage analysis
	TTDAnalysisResult codeCoverage;
	codeCoverage.type = TTDAnalysisType::CodeCoverage;
	codeCoverage.name = "Code Coverage";
	codeCoverage.description = QString("Analyzes which instructions were executed during the TTD trace.\n\n"
							  "This analysis extracts all executed instruction addresses from the TTD trace "
							  "and highlights them in the disassembly view with a green background.\n\n"
							  "For enhanced performance on large binaries, you can specify an address range "
							  "to analyze only a specific portion of the executable.\n\n"
							  "Status: ") + (m_controller && m_controller->IsTTD() ? "Available" : "TTD not available");
	codeCoverage.status = TTDAnalysisStatus::NotRun;
	codeCoverage.cachePath = getDefaultCachePath(TTDAnalysisType::CodeCoverage);
	codeCoverage.resultCount = 0;

	// Check if cache file exists
	QFileInfo cacheFile(codeCoverage.cachePath);
	QFileInfo dataFile(codeCoverage.cachePath + ".data");
	if (cacheFile.exists() && dataFile.exists())
	{
		codeCoverage.description += "\n\nCached results available from: " + cacheFile.lastModified().toString();
		codeCoverage.status = TTDAnalysisStatus::LoadedFromCache;
	}

	m_analysisResults.append(codeCoverage);

	// Update list widget
	m_analysisListWidget->clear();
	for (const auto& result : m_analysisResults)
	{
		QListWidgetItem* item = new QListWidgetItem(result.name);
		item->setData(Qt::UserRole, static_cast<int>(result.type));

		// Set icon based on status
		switch (result.status)
		{
		case TTDAnalysisStatus::NotRun:
			item->setIcon(style()->standardIcon(QStyle::SP_MediaPlay));
			break;
		case TTDAnalysisStatus::Running:
			item->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
			break;
		case TTDAnalysisStatus::Completed:
			item->setIcon(style()->standardIcon(QStyle::SP_DialogApplyButton));
			break;
		case TTDAnalysisStatus::Failed:
			item->setIcon(style()->standardIcon(QStyle::SP_DialogCancelButton));
			break;
		case TTDAnalysisStatus::LoadedFromCache:
			item->setIcon(style()->standardIcon(QStyle::SP_FileIcon));
			break;
		}

		m_analysisListWidget->addItem(item);
	}

	// Select first item by default
	if (m_analysisListWidget->count() > 0)
	{
		m_analysisListWidget->setCurrentRow(0);
		onAnalysisSelectionChanged();
	}
}

void TTDAnalysisDialog::onAnalysisSelectionChanged()
{
	int currentRow = m_analysisListWidget->currentRow();
	if (currentRow >= 0 && currentRow < m_analysisResults.size())
	{
		const TTDAnalysisResult& result = m_analysisResults[currentRow];
		m_analysisDetailsText->setText(result.description);

		// Update combo box
		int comboIndex = m_analysisTypeCombo->findData(static_cast<int>(result.type));
		if (comboIndex >= 0)
		{
			m_analysisTypeCombo->setCurrentIndex(comboIndex);
		}
	}

	updateButtonStates();
}

void TTDAnalysisDialog::onRunAnalysis()
{
	if (!m_controller)
	{
		QMessageBox::warning(this, "Error", "No debugger controller available");
		return;
	}

	if (!m_controller->IsTTD())
	{
		QMessageBox::warning(this, "Error", "Current adapter does not support TTD");
		return;
	}

	int currentRow = m_analysisListWidget->currentRow();
	if (currentRow < 0 || currentRow >= m_analysisResults.size())
		return;

	TTDAnalysisType analysisType = m_analysisResults[currentRow].type;

	// For code coverage analysis, require range specification
	if (analysisType == TTDAnalysisType::CodeCoverage && !m_useRangeCheckBox->isChecked())
	{
		QMessageBox::warning(this, "Range Required", "Code coverage analysis requires an address range to be specified");
		return;
	}

	// Check if range-based analysis is requested
	if (m_useRangeCheckBox->isChecked())
	{
		// Validate range inputs
		QString startText = m_startAddressEdit->text().trimmed();
		QString endText = m_endAddressEdit->text().trimmed();
		QString startTimeText = m_startTimeEdit->text().trimmed();
		QString endTimeText = m_endTimeEdit->text().trimmed();
		TTDPosition startTime, endTime;

		if (startText.isEmpty() || endText.isEmpty())
		{
			QMessageBox::warning(this, "Invalid Range", "Please enter both start and end addresses for range analysis");
			return;
		}

		// Parse addresses using the common address parser
		uint64_t startAddress = 0;
		std::string startError;
		if (!ParseAddress(startText, m_data, startAddress, &startError))
		{
			QMessageBox::warning(this, "Invalid Address",
				QString("Failed to parse start address '%1': %2").arg(startText).arg(QString::fromStdString(startError)));
			return;
		}

		uint64_t endAddress = 0;
		std::string endError;
		if (!ParseAddress(endText, m_data, endAddress, &endError))
		{
			QMessageBox::warning(this, "Invalid Address",
				QString("Failed to parse end address '%1': %2").arg(endText).arg(QString::fromStdString(endError)));
			return;
		}

		if (startTimeText.isEmpty())
		{
			startTime = TTDPosition(0, 0);
		}
		else
		{
			QStringList startTimeParts = startTimeText.split(u':');
			if (startTimeParts.size() != 2)
			{
				QMessageBox::warning(this, "Invalid Time", "Start time must be in the format 'sequence:step'");
				return;
			}
			bool seqOk, stepOk;
			uint64_t sequence = startTimeParts[0].toULongLong(&seqOk, 16);
			uint64_t step = startTimeParts[1].toULongLong(&stepOk, 16);
			if (!seqOk || !stepOk)
			{
				QMessageBox::warning(this, "Invalid Time", "Start time contains invalid numbers");
				return;
			}
			startTime = TTDPosition(sequence, step);
		}

		if (endTimeText.isEmpty())
		{
			endTime = TTDPosition(std::numeric_limits<uint64_t>::max(),std::numeric_limits<uint64_t>::max());
		}
		else
		{
			QStringList endTimeParts = endTimeText.split(u':');
			if (endTimeParts.size() != 2)
			{
				QMessageBox::warning(this, "Invalid Time", "End time must be in the format 'sequence:step'");
				return;
			}
			bool seqOk, stepOk;
			uint64_t sequence = endTimeParts[0].toULongLong(&seqOk, 16);
			uint64_t step = endTimeParts[1].toULongLong(&stepOk, 16);
			if (!seqOk || !stepOk)
			{
				QMessageBox::warning(this, "Invalid Time", "End time contains invalid numbers");
				return;
			}
			endTime = TTDPosition(sequence, step);
		}

		if (startAddress >= endAddress)
		{
			QMessageBox::warning(this, "Invalid Range", "Start address must be less than end address");
			return;
		}

		// Start range-based analysis in worker thread
		m_currentWorker = new TTDAnalysisWorker(m_controller, analysisType, startAddress, endAddress, startTime, endTime, this);
	}
	else
	{
		// For non-code coverage analyses, we could support full analysis
		// But since we've simplified the API, this path should not be reached for code coverage
		m_currentWorker = new TTDAnalysisWorker(m_controller, analysisType, this);
	}
	connect(m_currentWorker, &TTDAnalysisWorker::analysisProgress,
			this, &TTDAnalysisDialog::onAnalysisProgress);
	connect(m_currentWorker, &TTDAnalysisWorker::analysisCompleted,
			this, &TTDAnalysisDialog::onAnalysisCompleted);

	// Update UI for running state
	m_analysisResults[currentRow].status = TTDAnalysisStatus::Running;
	m_progressBar->setVisible(true);
	m_progressBar->setValue(0);
	m_statusLabel->setText("Running analysis...");

	updateButtonStates();
	populateAnalysisList();

	m_currentWorker->start();
}

void TTDAnalysisDialog::onAnalysisProgress(int percentage, const QString& message)
{
	m_progressBar->setValue(percentage);
	m_statusLabel->setText(message);
}

void TTDAnalysisDialog::onAnalysisCompleted(bool success, const QString& message, size_t resultCount)
{
	int currentRow = m_analysisListWidget->currentRow();
	if (currentRow >= 0 && currentRow < m_analysisResults.size())
	{
		QMutexLocker locker(&m_resultsMutex);

		m_analysisResults[currentRow].status = success ? TTDAnalysisStatus::Completed : TTDAnalysisStatus::Failed;
		m_analysisResults[currentRow].resultCount = resultCount;
		m_analysisResults[currentRow].lastRun = QDateTime::currentDateTime();
		m_analysisResults[currentRow].errorMessage = success ? QString() : message;

		// Auto-save if enabled
		if (success && m_autoCacheCheckBox->isChecked())
		{
			saveAnalysisResults(m_analysisResults[currentRow]);
		}
	}

	m_progressBar->setVisible(false);
	m_statusLabel->setText(message);

	if (m_currentWorker)
	{
		m_currentWorker->deleteLater();
		m_currentWorker = nullptr;
	}

	updateButtonStates();
	populateAnalysisList();

	if (!success)
	{
		QMessageBox::warning(this, "Analysis Failed", message);
	}
	else
	{
		// Refresh the view to make coverage visible immediately
		refreshViewAndEnableRenderLayer();
	}
}

void TTDAnalysisDialog::onSaveResults()
{
	int currentRow = m_analysisListWidget->currentRow();
	if (currentRow < 0 || currentRow >= m_analysisResults.size())
		return;

	const TTDAnalysisResult& result = m_analysisResults[currentRow];
	if (result.status != TTDAnalysisStatus::Completed)
	{
		QMessageBox::information(this, "Save Results", "No completed analysis results to save");
		return;
	}

	if (saveAnalysisResults(result))
	{
		QMessageBox::information(this, "Save Results", "Analysis results saved successfully");
	}
	else
	{
		QMessageBox::warning(this, "Save Results", "Failed to save analysis results");
	}
}

void TTDAnalysisDialog::onLoadResults()
{
	int currentRow = m_analysisListWidget->currentRow();
	if (currentRow < 0 || currentRow >= m_analysisResults.size())
		return;

	QMutexLocker locker(&m_resultsMutex);

	TTDAnalysisResult& result = m_analysisResults[currentRow];
	if (loadAnalysisResults(result))
	{
		result.status = TTDAnalysisStatus::LoadedFromCache;
		locker.unlock();

		populateAnalysisList();
		QMessageBox::information(this, "Load Results", "Analysis results loaded successfully");

		// Refresh the view to show the loaded coverage
		refreshViewAndEnableRenderLayer();
	}
	else
	{
		QMessageBox::warning(this, "Load Results", "Failed to load analysis results");
	}
}

void TTDAnalysisDialog::onClearCache()
{
	QString cacheDir = m_cachePathEdit->text();
	QDir dir(cacheDir);

	if (!dir.exists())
	{
		QMessageBox::information(this, "Clear Cache", "Cache directory does not exist");
		return;
	}

	if (QMessageBox::question(this, "Clear Cache",
							 "Are you sure you want to clear all cached analysis results?",
							 QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes)
	{
		// Clear cache files
		QStringList filters;
		filters << "*.json" << "*.cache";
		QFileInfoList files = dir.entryInfoList(filters, QDir::Files);

		int deletedCount = 0;
		for (const QFileInfo& fileInfo : files)
		{
			if (QFile::remove(fileInfo.absoluteFilePath()))
				deletedCount++;
		}

		QMessageBox::information(this, "Clear Cache",
								QString("Cleared %1 cache files").arg(deletedCount));
	}
}

void TTDAnalysisDialog::onRefreshStatus()
{
	updateAnalysisStatus();
}

void TTDAnalysisDialog::updateAnalysisStatus()
{
	if (!m_controller)
		return;

	// Check if TTD is available
	bool ttdAvailable = m_controller->IsTTD();

	QString statusText = ttdAvailable ? "TTD Available" : "TTD Not Available";
	if (ttdAvailable)
	{
		// Add more detailed status information
		statusText += " - Ready for analysis";
	}

	// Update status only if not currently running an analysis
	if (!m_currentWorker)
	{
		m_statusLabel->setText(statusText);
	}
}

void TTDAnalysisDialog::updateButtonStates()
{
	bool ttdAvailable = m_controller && m_controller->IsTTD();
	bool analysisRunning = (m_currentWorker != nullptr);

	int currentRow = m_analysisListWidget->currentRow();
	bool hasSelection = (currentRow >= 0 && currentRow < m_analysisResults.size());

	m_runButton->setEnabled(ttdAvailable && !analysisRunning && hasSelection);

	bool hasCompletedResults = false;
	if (hasSelection)
	{
		const TTDAnalysisResult& result = m_analysisResults[currentRow];
		hasCompletedResults = (result.status == TTDAnalysisStatus::Completed);
	}

	m_saveButton->setEnabled(hasCompletedResults && !analysisRunning);
	m_loadButton->setEnabled(hasSelection && !analysisRunning);
	m_clearCacheButton->setEnabled(!analysisRunning);
}

QString TTDAnalysisDialog::getDefaultCachePath(TTDAnalysisType type)
{
	QString baseDir = m_cachePathEdit ? m_cachePathEdit->text() :
					 QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/ttd_analysis";

	QString fileName;
	switch (type)
	{
	case TTDAnalysisType::CodeCoverage:
		fileName = "code_coverage.json";
		break;
	default:
		fileName = "unknown_analysis.json";
		break;
	}

	return QDir(baseDir).absoluteFilePath(fileName);
}

bool TTDAnalysisDialog::saveAnalysisResults(const TTDAnalysisResult& result)
{
	QString cachePath = result.cachePath;
	if (cachePath.isEmpty())
		return false;

	// Ensure cache directory exists
	QDir cacheDir = QFileInfo(cachePath).dir();
	if (!cacheDir.exists())
	{
		cacheDir.mkpath(".");
	}

	// Save metadata as JSON
	QJsonObject json;
	json["type"] = static_cast<int>(result.type);
	json["name"] = result.name;
	json["description"] = result.description;
	json["resultCount"] = static_cast<qint64>(result.resultCount);
	json["lastRun"] = result.lastRun.toString(Qt::ISODate);
	json["status"] = static_cast<int>(result.status);

	QJsonDocument doc(json);

	QFile file(cachePath);
	if (!file.open(QIODevice::WriteOnly))
		return false;

	file.write(doc.toJson());
	file.close();

	// Save actual analysis data using controller
	if (result.type == TTDAnalysisType::CodeCoverage && m_controller)
	{
		QString dataPath = cachePath + ".data";
		return m_controller->SaveCodeCoverageToFile(dataPath.toStdString());
	}

	return true;
}

bool TTDAnalysisDialog::loadAnalysisResults(TTDAnalysisResult& result)
{
	QString cachePath = result.cachePath;
	if (cachePath.isEmpty())
		return false;

	QFile file(cachePath);
	if (!file.open(QIODevice::ReadOnly))
		return false;

	QJsonParseError error;
	QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &error);
	if (error.error != QJsonParseError::NoError)
		return false;

	QJsonObject json = doc.object();

	result.resultCount = json["resultCount"].toVariant().toULongLong();
	result.lastRun = QDateTime::fromString(json["lastRun"].toString(), Qt::ISODate);

	file.close();

	// Load actual analysis data using controller
	if (result.type == TTDAnalysisType::CodeCoverage && m_controller)
	{
		QString dataPath = cachePath + ".data";
		QFileInfo dataFile(dataPath);
		if (dataFile.exists())
		{
			return m_controller->LoadCodeCoverageFromFile(dataPath.toStdString());
		}
	}

	return true;
}

void TTDAnalysisDialog::refreshViewAndEnableRenderLayer()
{
	// Use the stored UI context to refresh the view
	if (!m_context)
		return;

	// Refresh the current view contents to show the coverage immediately
	// This will trigger the render layers to update and display the coverage
	m_context->refreshCurrentViewContents();

	// Check if the TTD Coverage render layer is registered
	Ref<RenderLayer> ttdLayer = RenderLayer::GetByName("TTD Coverage");
	if (!ttdLayer)
	{
		// This shouldn't happen, but log an error if the layer isn't registered
		LogError("TTD Coverage render layer is not registered");
	}
}
