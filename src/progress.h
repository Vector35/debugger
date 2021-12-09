#include <QtWidgets/QProgressDialog>

class ProgressIndicator
{
	QProgressDialog m_progress;
	bool m_maxSet;
	std::chrono::steady_clock::time_point m_lastUpdate;

public:
	ProgressIndicator(QWidget* parent, const QString& title, const QString& text, const QString& cancel=QString());
	void update(uint64_t cur, uint64_t total);
	bool wasCancelled() const { return m_progress.wasCanceled(); }
	void cancel();
};
