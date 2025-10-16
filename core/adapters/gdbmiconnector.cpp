#include "gdbmiconnector.h"
#include <iostream>
#include <regex>
#include <binaryninjaapi.h>
#include <fcntl.h>
#ifdef WIN32
#else
#include <spawn.h>
#include <sys/wait.h>
#include <cstring> // for strerror
// For Linux/macOS, we need the environment variables
extern char** environ;
#endif

using namespace BinaryNinja;

// MiValue implementation (a simple recursive-descent parser for GDB MI results)
MiValue::MiValue(const std::string& str) : m_string(str) {}
const MiValue& MiValue::operator[](const std::string& key) const
{
    static MiValue empty;
    auto it = m_dict.find(key);
    return (it != m_dict.end()) ? it->second : empty;
}
const MiValue& MiValue::operator[](size_t index) const
{
    static MiValue empty;
    return (index < m_list.size()) ? m_list[index] : empty;
}
const std::string& MiValue::GetString() const { return m_string; }
const std::vector<MiValue>& MiValue::GetList() const { return m_list; }
const std::map<std::string, MiValue>& MiValue::GetDict() const { return m_dict; }
size_t MiValue::size() const { return m_isList ? m_list.size() : m_dict.size(); }
bool MiValue::Exists(const std::string& key) const { return m_dict.contains(key); }
MiValue MiValue::Parse(const std::string& data)
{
	MiValue result;
	size_t pos = 0;

	auto skip_ws = [&]() {
		while (pos < data.size() && isspace(data[pos]))
			pos++;
	};

	auto parse_string = [&]() -> std::string {
		if (data[pos] != '"')
			return "";
		pos++;
		std::string str;
		while (pos < data.size() && data[pos] != '"')
		{
			if (data[pos] == '\\' && pos + 1 < data.size())
			{
				str += data[pos + 1];
				pos += 2;
			}
			else
			{
				str += data[pos];
				pos++;
			}
		}
		if (pos < data.size())
			pos++; // Skip closing quote
		return str;
	};

	std::function<MiValue()> parse_value = [&]() -> MiValue {
		skip_ws();
		if (pos >= data.size())
			return MiValue("");
		if (data[pos] == '"')
			return MiValue(parse_string());
		if (data[pos] == '{')
		{
			pos++;
			MiValue dict;
			dict.m_isDict = true;
			while (pos < data.size() && data[pos] != '}')
			{
				skip_ws();
				size_t eq = data.find('=', pos);
				if (eq != std::string::npos)
				{
					auto key = data.substr(pos, eq - pos);
					pos = eq + 1;
					dict.m_dict[key] = parse_value();
					skip_ws();
					if (pos < data.size() && data[pos] == ',')
						pos++;
				}
				else
				{
					break;
				}
			}
			if (pos < data.size())
				pos++; // Skip '}'
			return dict;
		}
		if (data[pos] == '[')
		{
			pos++;
			MiValue list;
			list.m_isList = true;
			while (pos < data.size() && data[pos] != ']')
			{
				skip_ws();

				// Check if this is a child=value pattern (common in GDB MI arrays)
				size_t child_end = data.find('=', pos);
				size_t next_comma = data.find(',', pos);
				size_t next_bracket = data.find(']', pos);

				if (child_end != std::string::npos &&
					child_end < next_comma && child_end < next_bracket && child_end - pos > 0 &&
					data[pos] != '{' && data[pos] != '[') // Don't apply to dicts or arrays
				{
					// Extract the key (e.g., "child")
					std::string key = data.substr(pos, child_end - pos);
					pos = child_end + 1; // Skip '='

					// Parse the value
					MiValue value = parse_value();

					// Create a dictionary for this key-value pair
					MiValue dict;
					dict.m_isDict = true;
					dict.m_dict[key] = value;
					list.m_list.push_back(dict);
				}
				else
				{
					// Normal array element
					list.m_list.push_back(parse_value());
				}
				
				skip_ws();
				if (pos < data.size() && data[pos] == ',')
					pos++;
			}
			if (pos < data.size())
				pos++; // Skip ']'
			return list;
		}
		// This is not a valid MI value. It might be a raw string.
		// For now, we just log it and return an empty value.
		size_t end = data.find_first_of(",}]", pos);
		if (end == std::string::npos)
			end = data.size();
		LogDebug("Raw MI value: %s", data.substr(pos, end - pos).c_str());
		result = MiValue(data.substr(pos, end - pos));
		pos = end;
		return result;
	};

	// Main parsing logic starts here
	result.m_isDict = true;
	while (pos < data.size())
	{
		skip_ws();
		size_t eq = data.find('=', pos);
		if (eq != std::string::npos)
		{
			auto key = data.substr(pos, eq - pos);
			pos = eq + 1;
			result.m_dict[key] = parse_value();
			skip_ws();
			if (pos < data.size() && data[pos] == ',')
				pos++;
		}
		else
		{
			if (data[pos] == '"')
				return MiValue(parse_string());
			// Fallback, just give it as is
			return MiValue(data.substr(pos, data.size()));
		}
	}
	return result;
}

GdbMiConnector::GdbMiConnector(const std::string& gdbPath, const std::string& targetExecutable)
    : m_gdbPath(gdbPath), m_targetExecutable(targetExecutable)
{
}

GdbMiConnector::~GdbMiConnector()
{
    Stop();
}

void GdbMiConnector::Stop()
{
	if (!m_running)
		return;

	LogInfo("GDB MI connector: Starting graceful shutdown...");
	SendCommand("-gdb-exit", 200);
	// Set running flag to false first to signal reader thread to exit
	m_running = false;

	// Close file handles to wake up reader thread blocked on I/O
	CloseFileHandles();

	// Wait for the reader thread to finish with a timeout
	if (m_readerThread.joinable())
	{
		LogInfo("GDB MI connector: Waiting for reader thread to finish...");
		m_readerThread.join();
	}

	// Try to terminate GDB process if still running
	TerminateGdbProcess();
	LogInfo("GDB MI connector: Shutdown completed");
}

bool GdbMiConnector::Start()
{
    if (m_running)
        return true;

#ifdef WIN32
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE gdb_stdout_write = NULL;
    HANDLE gdb_stdin_read = NULL;

    if (!CreatePipe(&m_gdb_stdout_read, &gdb_stdout_write, &saAttr, 0)) return false;
    if (!SetHandleInformation(m_gdb_stdout_read, HANDLE_FLAG_INHERIT, 0)) return false;
    if (!CreatePipe(&gdb_stdin_read, &m_gdb_stdin_write, &saAttr, 0)) return false;
    if (!SetHandleInformation(m_gdb_stdin_write, HANDLE_FLAG_INHERIT, 0)) return false;

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(STARTUPINFOA));
    si.cb = sizeof(STARTUPINFOA);
    si.hStdError = gdb_stdout_write;
    si.hStdOutput = gdb_stdout_write;
    si.hStdInput = gdb_stdin_read;
    si.dwFlags |= STARTF_USESTDHANDLES;

    std::string cmd = m_gdbPath + " -q --interpreter=mi2";
    if (!m_targetExecutable.empty()) {
        cmd += " \"" + m_targetExecutable + "\"";
    }

    if (!CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &m_pi))
    {
        CloseHandle(m_gdb_stdout_read);
        CloseHandle(gdb_stdout_write);
        CloseHandle(gdb_stdin_read);
        CloseHandle(m_gdb_stdin_write);
        return false;
    }
    CloseHandle(gdb_stdout_write);
    CloseHandle(gdb_stdin_read);
#else
    int gdb_stdin_pipe[2];
    int gdb_stdout_pipe[2];

    if (pipe(gdb_stdin_pipe) != 0 || pipe(gdb_stdout_pipe) != 0) return false;

    std::vector<char*> argv;
    std::string gdbPathCopy = m_gdbPath;
    std::string miArg = "-q";
    std::string miArg2 = "--interpreter=mi2";
    std::string targetCopy = m_targetExecutable;

    argv.push_back(const_cast<char*>(gdbPathCopy.c_str()));
    argv.push_back(const_cast<char*>(miArg.c_str()));
    argv.push_back(const_cast<char*>(miArg2.c_str()));
    if (!m_targetExecutable.empty()) {
        argv.push_back(const_cast<char*>(targetCopy.c_str()));
    }
    argv.push_back(nullptr);

    posix_spawn_file_actions_t file_actions;
    posix_spawn_file_actions_init(&file_actions);
    posix_spawn_file_actions_addclose(&file_actions, gdb_stdin_pipe[1]);
    posix_spawn_file_actions_addclose(&file_actions, gdb_stdout_pipe[0]);
    posix_spawn_file_actions_adddup2(&file_actions, gdb_stdin_pipe[0], STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&file_actions, gdb_stdout_pipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&file_actions, gdb_stdout_pipe[1], STDERR_FILENO);
    
    int result = posix_spawn(&m_pid, m_gdbPath.c_str(), &file_actions, nullptr, argv.data(), environ);
    
    close(gdb_stdin_pipe[0]);
    close(gdb_stdout_pipe[1]);

    if (result != 0) {
        m_pid = -1;
        close(gdb_stdin_pipe[1]);
        close(gdb_stdout_pipe[0]);
        return false;
    }

    m_gdb_stdin_write = gdb_stdin_pipe[1];
    m_gdb_stdout_read = gdb_stdout_pipe[0];
#endif

    m_running = true;
    m_readerThread = std::thread(&GdbMiConnector::ReaderThread, this);
    return true;
}

MiRecord GdbMiConnector::SendCommand(const std::string& command, int timeout_ms)
{
    if (!m_running) return {};

    if (std::this_thread::get_id() == m_readerThread.get_id()) {
        LogError("SendCommand called from reader thread; would deadlock");
        return {};
    }

    long token = m_nextToken++;
    std::string fullCommand = std::to_string(token) + command + "\n";
    
    try {
#ifdef WIN32
        DWORD bytesWritten;
        if (!WriteFile(m_gdb_stdin_write, fullCommand.c_str(), static_cast<DWORD>(fullCommand.length()), &bytesWritten, NULL)) {
            DWORD error = GetLastError();
            LogError("Failed to write to GDB stdin, error: %lu", error);
            m_running = false;
            return {};
        }
#else
        ssize_t bytesWritten = write(m_gdb_stdin_write, fullCommand.c_str(), fullCommand.length());
        if (bytesWritten < 0) {
            int error = errno;
            LogError("Failed to write to GDB stdin, error: %d (%s)", error, strerror(error));
            
            // Handle specific pipe errors
            if (error == EPIPE || error == ECONNRESET) {
                LogError("GDB process pipe broken - process likely terminated");
                m_running = false;
            } else if (error == EBADF) {
                LogError("Invalid file descriptor for GDB stdin");
                m_running = false;
            }
            return {};
        } else if (static_cast<size_t>(bytesWritten) != fullCommand.length()) {
            LogWarn("Partial write to GDB stdin: %zd of %zu bytes", bytesWritten, fullCommand.length());
        }
#endif
    } catch (const std::exception& e) {
        LogError("Exception while writing to GDB: %s", e.what());
        m_running = false;
        return {};
    } catch (...) {
        LogError("Unknown exception while writing to GDB");
        m_running = false;
        return {};
    }
    
    std::unique_lock lock(m_mutex);
    LogDebug("GDB->: %s", fullCommand.c_str());
    
    // Wait for response with timeout
    if (m_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&] { return m_responses.count(token) || !m_running; }))
    {
        MiRecord record = m_responses[token];
        m_responses.erase(token);
        return record;
    } else {
        LogWarn("Timeout waiting for GDB response to command: %s", command.c_str());
        return {};
    }
}

void GdbMiConnector::ReaderThread()
{
    std::string currentLine;
    char buffer[8192] = {0};

    try {
#ifndef WIN32
        // Make the read fd non-blocking so we can drain per select wakeup
        int flags = fcntl(m_gdb_stdout_read, F_GETFL, 0);
        fcntl(m_gdb_stdout_read, F_SETFL, flags | O_NONBLOCK);

        while (m_running)
        {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(m_gdb_stdout_read, &rfds);

            struct timeval tv = {0};
            tv.tv_sec = 0;
            tv.tv_usec = 200000; // 200ms

            int retval = select(m_gdb_stdout_read + 1, &rfds, nullptr, nullptr, &tv);
            if (retval == -1)
            {
                int selectError = errno;
                if (selectError != EINTR) { // Ignore interrupted system calls
                    LogError("Select error from GDB: %d (%s)", selectError, strerror(selectError));
                    m_running = false;
                    break;
                }
                continue;
            }
            if (retval == 0)
            {
                continue; // Timeout, check if we should continue
            }

            while (m_running)
            {
                ssize_t n = read(m_gdb_stdout_read, buffer, sizeof(buffer)-1);
                if (n > 0)
                {
                    buffer[n] = 0;
                    // Frame by CR or LF; strip CRs
                    for (ssize_t i = 0; i < n; ++i)
                    {
                        char c = buffer[i];

                        if (c == '\r' || c == '\n')
                        {
                            if (!currentLine.empty())
                            {
                                // Trim any leftover CRs or spaces from ends
                                size_t start = 0;
                                while (start < currentLine.size() &&
                                       (currentLine[start] == '\r' || currentLine[start] == ' ' || currentLine[start] == '\t'))
                                    ++start;
                                size_t end = currentLine.size();
                                while (end > start &&
                                       (currentLine[end - 1] == '\r' || currentLine[end - 1] == ' ' || currentLine[end - 1] == '\t'))
                                    --end;

                                std::string line = currentLine.substr(start, end - start);

                                if (!line.empty())
                                {
                                    MiRecord record = ParseLine(line);
                                    if (record.token.has_value() && record.type == '^')
                                    {
                                        std::unique_lock<std::mutex> lock(m_mutex);
                                        // LogDebug("Notify about response %ld", *record.token);
                                        m_responses[*record.token] = record;
                                        m_cv.notify_all();
                                    }
                                    else if (m_asyncCallback && record.type != '^')
                                    {
                                        // Do not block the reader; just forward
                                        m_asyncCallback(record);
                                    }
                                }
                            }
                            currentLine.clear();
                        }
                        else
                        {
                            if (c != '\0') // ignore NULs just in case
                                currentLine += c;
                        }
                    }
                    continue; // try reading more (drain)
                }

                if (n == -1 && errno == EAGAIN)
                    break; // no more data for now

                if (n == 0)
                {
                    // EOF - GDB process has terminated
                    LogInfo("GDB process EOF - connection closed");
                    m_running = false;
                    break;
                }

                // n == -1 and not EAGAIN
                int readError = errno;
                LogError("Read error from GDB: %d (%s)", readError, strerror(readError));
                
                // Handle specific pipe errors
                if (readError == EPIPE || readError == ECONNRESET) {
                    LogError("GDB process pipe broken - process terminated");
                } else if (readError == EBADF) {
                    LogError("Invalid file descriptor for GDB stdout");
                }
                
                m_running = false;
                break;
            }
        }
#else
        DWORD bytesRead;
        while (m_running)
        {
            if (!ReadFile(m_gdb_stdout_read, buffer, sizeof(buffer), &bytesRead, NULL))
            {
                DWORD error = GetLastError();
                if (error == ERROR_BROKEN_PIPE)
                {
                    LogInfo("GDB process pipe broken - connection closed");
                }
                else
                {
                    LogError("ReadFile error from GDB: %lu", error);
                }
                m_running = false;
                break;
            }

            if (bytesRead == 0)
            {
                // EOF
                LogInfo("GDB process EOF - connection closed");
                m_running = false;
                break;
            }

            // Similar CR/LF framing on Windows
            for (DWORD i = 0; i < bytesRead; ++i)
            {
                char c = buffer[i];
                if (c == '\r' || c == '\n')
                {
                    if (!currentLine.empty())
                    {
                        // Trim CR/space
                        size_t start = 0;
                        while (start < currentLine.size() &&
                               (currentLine[start] == '\r' || currentLine[start] == ' ' || currentLine[start] == '\t'))
                            ++start;
                        size_t end = currentLine.size();
                        while (end > start &&
                               (currentLine[end - 1] == '\r' || currentLine[end - 1] == ' ' || currentLine[end - 1] == '\t'))
                            --end;
                        std::string line = currentLine.substr(start, end - start);

                        if (!line.empty())
                        {
                            MiRecord record = ParseLine(line);
                            if (record.token.has_value() && record.type == '^')
                            {
                                std::unique_lock<std::mutex> lock(m_mutex);
                                LogDebug("Notify about response %ld", *record.token);
                                m_responses[*record.token] = record;
                                m_cv.notify_all();
                            }
                            else if (m_asyncCallback)
                            {
                                m_asyncCallback(record);
                            }
                        }
                    }
                    currentLine.clear();
                }
                else
                {
                    if (c != '\0')
                        currentLine += c;
                }
            }
        }
#endif
    } catch (const std::exception& e) {
        LogError("Exception in GDB reader thread: %s", e.what());
        m_running = false;
    } catch (...) {
        LogError("Unknown exception in GDB reader thread");
        m_running = false;
    }

    LogInfo("GDB reader thread exiting");
}

MiRecord GdbMiConnector::ParseLine(const std::string &line) {
  LogDebug("GDB<-: %s", line.c_str());

  MiRecord record;
  record.fullLine = line;

  // Normalize CRLF
  std::string s = line;
  if (!s.empty() && s.back() == '\r')
    s.pop_back();

  if (s == "(gdb)") {
    m_gdbReady = true;
    return record;
  }

  size_t pos = 0;

  // Parse optional token
  if (pos < s.size() && isdigit(static_cast<unsigned char>(s[pos]))) {
    try {
      record.token = std::stol(s, &pos);
    //   LogDebug("Got response for %ld", *record.token);
    } catch (...) {
      LogWarn("Can't parse token in line: %s", s.c_str());
      pos = 0;
      record.token.reset();
    }
  }

  if (pos >= s.size())
    return record;

  // Parse record type (^, *, +, ~, @, &, =)
  record.type = s[pos++];

  // Result-record: token? '^' result-class [',' results]
  // Stream/async output doesn't have a result-class, but we still parse the remainder consistently
  if (pos <= s.size()) {
    size_t comma = s.find(',', pos);
    if (comma != std::string::npos) {
      record.command = s.substr(pos, comma - pos); // result-class or stream text prefix
      record.payload = s.substr(comma + 1);        // results or rest
    } else {
      record.command = s.substr(pos);
    }
  }

  return record;
}

// Helper method to terminate GDB process gracefully
bool GdbMiConnector::TerminateGdbProcess()
{
#ifdef WIN32
    if (m_pi.hProcess)
    {
        // Try graceful termination first
        if (TerminateProcess(m_pi.hProcess, 0))
        {
            LogInfo("GDB process terminated gracefully");
            return true;
        }
        else
        {
            DWORD error = GetLastError();
            LogError("Failed to terminate GDB process, error: %lu", error);
            return false;
        }
    }
#else
    if (m_pid > 0)
    {
        int status;
        
        // Check if process is still running
        if (waitpid(m_pid, &status, WNOHANG) == 0)
        {
            // Process is still running, try graceful shutdown first
            LogInfo("Attempting graceful shutdown of GDB process (PID: %d)", m_pid);
            kill(m_pid, SIGTERM);
            
            // Wait up to 2 seconds for graceful shutdown
            auto start = std::chrono::steady_clock::now();
            while (std::chrono::steady_clock::now() - start < std::chrono::seconds(2))
            {
                if (waitpid(m_pid, &status, WNOHANG) != 0)
                {
                    LogInfo("GDB process (PID: %d) exited gracefully", m_pid);
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            
            // If still running, force termination
            if (waitpid(m_pid, &status, WNOHANG) == 0)
            {
                LogWarn("GDB process (PID: %d) did not exit gracefully, forcing termination", m_pid);
                kill(m_pid, SIGKILL);
                waitpid(m_pid, &status, 0);
                LogInfo("GDB process (PID: %d) terminated with SIGKILL", m_pid);
            }
        }
        else
        {
            LogInfo("GDB process (PID: %d) already exited", m_pid);
        }
        return true;
    }
#endif
    return true;
}

// Helper method to close all file handles
void GdbMiConnector::CloseFileHandles()
{
#ifdef WIN32
    if (m_gdb_stdin_write && m_gdb_stdin_write != INVALID_HANDLE_VALUE)
    {
        CloseHandle(m_gdb_stdin_write);
        m_gdb_stdin_write = NULL;
    }
    if (m_gdb_stdout_read && m_gdb_stdout_read != INVALID_HANDLE_VALUE)
    {
        CloseHandle(m_gdb_stdout_read);
        m_gdb_stdout_read = NULL;
    }
    if (m_pi.hProcess)
    {
        CloseHandle(m_pi.hProcess);
        m_pi.hProcess = NULL;
    }
    if (m_pi.hThread)
    {
        CloseHandle(m_pi.hThread);
        m_pi.hThread = NULL;
    }
#else
    if (m_gdb_stdin_write >= 0)
    {
        close(m_gdb_stdin_write);
        m_gdb_stdin_write = -1;
    }
    if (m_gdb_stdout_read >= 0)
    {
        close(m_gdb_stdout_read);
        m_gdb_stdout_read = -1;
    }
#endif
}
