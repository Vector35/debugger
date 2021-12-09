#include "progress.h"
using namespace std;

ProgressIndicator::ProgressIndicator(QWidget* parent, const QString& title, const QString& text, const QString& cancel): m_progress(parent)
{
	m_progress.setWindowTitle(title);
	m_progress.setLabelText(text);
	m_progress.setMinimumDuration(200);
	m_progress.setWindowModality(Qt::WindowModal);
	m_progress.setCancelButtonText(cancel);
	m_progress.setValue(m_progress.minimum());
	m_maxSet = false;
	m_lastUpdate = chrono::steady_clock::now();
}


void ProgressIndicator::update(uint64_t cur, uint64_t total)
{
	if (total > INT32_MAX)
	{
		cur /= (total / INT32_MAX);
		total = INT32_MAX;
	}

	if (!m_maxSet || ((int)total != m_progress.maximum()))
	{
		m_progress.setMaximum((int)total);
		m_maxSet = true;
	}

	chrono::steady_clock::time_point curTime = chrono::steady_clock::now();
	if (cur == total || chrono::duration_cast<chrono::milliseconds>(curTime - m_lastUpdate).count() >= 100)
	{
		m_progress.setValue((int)cur);
		m_lastUpdate = chrono::steady_clock::now();
	}
}


void ProgressIndicator::cancel()
{
	m_progress.cancel();
}
