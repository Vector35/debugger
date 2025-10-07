#pragma once
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <optional>
#include <map>
#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <signal.h>
#endif

// Represents a parsed GDB MI record
struct MiRecord
{
    std::string fullLine; // 1^done,threads=[{...}]
    std::optional<long> token; // 1,2,3,4,5... (autoincremented correlation counter)
    char type; // '^', '*', '+', '~', '@', '&'
    std::string command; // "done", "error", "stopped", "running"
    std::string payload; // threads=[{...}]
};
// Helper class to parse MI key-value pairs
class MiValue
{
    std::map<std::string, MiValue> m_dict;
    std::vector<MiValue> m_list;
    std::string m_string;
    bool m_isList = false;
    bool m_isDict = false;

public:
    MiValue() = default;
    MiValue(const std::string& str);
    static MiValue Parse(const std::string& data);

    const MiValue& operator[](const std::string& key) const;
    const MiValue& operator[](size_t index) const;
    const std::string& GetString() const;
    const std::vector<MiValue>& GetList() const;
    const std::map<std::string, MiValue>& GetDict() const;
    size_t size() const;
    bool IsList() const { return m_isList; }
    bool IsDict() const { return m_isDict; }
    bool IsString() const { return !m_isList && !m_isDict; }
    bool Exists(const std::string& key) const;
};

class GdbMiConnector
{
	std::string m_gdbPath;
    std::string m_targetExecutable;
    std::thread m_readerThread;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::map<long, MiRecord> m_responses;
    std::queue<MiRecord> m_asyncRecords;
    long m_nextToken = 1;
    bool m_running = false;
    bool m_gdbReady = false;

#ifdef WIN32
    PROCESS_INFORMATION m_pi;
    HANDLE m_gdb_stdin_write = NULL;
    HANDLE m_gdb_stdout_read = NULL;
#else
    pid_t m_pid = -1;
    int m_gdb_stdin_write = -1;
    int m_gdb_stdout_read = -1;
#endif
    std::function<void(const MiRecord&)> m_asyncCallback; // ADDED: Callback for async records

    void ReaderThread();
    MiRecord ParseLine(const std::string& line);
    
    // Helper methods for robust process management
    bool TerminateGdbProcess();
    void CloseFileHandles();

public:
    GdbMiConnector(const std::string& gdbPath, const std::string& targetExecutable);
    ~GdbMiConnector();
    
    void SetAsyncCallback(std::function<void(const MiRecord&)> cb) { m_asyncCallback = cb; }

    bool Start();
    void Stop();
    bool IsRunning() const { return m_running; }

    // Synchronously send a command and wait for its result record (^done, ^error, etc.)
    MiRecord SendCommand(const std::string& command, int timeout_ms = 1000);
};