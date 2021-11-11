#include "queuedadapter.h"
#include <memory>
#include <cstring>
#ifdef WIN32
#include <windows.h>
#undef min
#undef max
#else
#include <unistd.h>
#include <spawn.h>
#include <csignal>
#endif
#include <algorithm>
#include <string>
#include <chrono>
#include <thread>
#include <cstdio>
#include <iostream>
#include <string_view>
#include <regex>
#include <stdexcept>
#include <pugixml/pugixml.hpp>
#include <binaryninjacore.h>
#include <binaryninjaapi.h>
#include <lowlevelilinstruction.h>
#include <mediumlevelilinstruction.h>
#include <highlevelilinstruction.h>

using namespace BinaryNinja;
using namespace std;


QueuedAdapter::QueuedAdapter(DebugAdapter* adapter): m_adapter(adapter)
{
    std::thread worker([&](){
        Worker();
    });
    worker.detach();
}


QueuedAdapter::~QueuedAdapter()
{

}


bool QueuedAdapter::Execute(const std::string& path)
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->Execute(path);
        sem.Release();
    });

    lock.unlock();
    sem.Wait();
    return ret;
}


bool QueuedAdapter::ExecuteWithArgs(const std::string& path, const std::vector<std::string>& args)
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&, path, args]{
        ret = m_adapter->ExecuteWithArgs(path, args);
        sem.Release();
    });

    lock.unlock();
    sem.Wait();
    return ret;
}


bool QueuedAdapter::Attach(std::uint32_t pid)
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&, pid]{
        ret = m_adapter->Attach(pid);
        sem.Release();
    });

    lock.unlock();
    sem.Wait();
    return ret;
}


bool QueuedAdapter::Connect(const std::string& server, std::uint32_t port)
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&, server, port]{
        ret = m_adapter->Connect(server, port);
        sem.Release();
    });

    lock.unlock();
    sem.Wait();
    return ret;
}


void QueuedAdapter::Detach()
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    Semaphore sem;
    m_queue.push([&]{
        m_adapter->Detach();
        sem.Release();
    });

    lock.unlock();
    sem.Wait();
}


void QueuedAdapter::Quit()
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    Semaphore sem;
    m_queue.push([&]{
        m_adapter->Quit();
        sem.Release();
    });

    lock.unlock();
    sem.Wait();
}


std::vector<DebugThread> QueuedAdapter::GetThreadList()
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    std::vector<DebugThread> threads;
    Semaphore sem;
    m_queue.push([&]{
        threads = m_adapter->GetThreadList();
        sem.Release();
    });

    lock.unlock();
    sem.Wait();
    return threads;
}


DebugThread QueuedAdapter::GetActiveThread() const
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    DebugThread thread;
    Semaphore sem;
    m_queue.push([&]{
        thread = m_adapter->GetActiveThread();
        sem.Release();
    });

    lock.unlock();
    sem.Wait();
    return thread;
}


std::uint32_t QueuedAdapter::GetActiveThreadId() const
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    std::uint32_t tid;
    Semaphore sem;
    m_queue.push([&]{
        tid = m_adapter->GetActiveThreadId();
        sem.Release();
    });

    lock.unlock();
    sem.Wait();
    return tid;
}


bool QueuedAdapter::SetActiveThread(const DebugThread& thread)
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->SetActiveThread(thread);
        sem.Release();
    });

    lock.unlock();
    sem.Wait();
    return ret;
}


bool QueuedAdapter::SetActiveThreadId(std::uint32_t tid)
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->SetActiveThreadId(tid);
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


DebugBreakpoint QueuedAdapter::AddBreakpoint(std::uintptr_t address, unsigned long breakpoint_type)
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    DebugBreakpoint ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->AddBreakpoint(address, breakpoint_type);
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


std::vector<DebugBreakpoint> QueuedAdapter::AddBreakpoints(const std::vector<std::uintptr_t>& breakpoints)
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    std::vector<DebugBreakpoint> ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->AddBreakpoints(breakpoints);
        sem.Release();
    });

    lock.unlock();
    sem.Wait();
    return ret;
}


bool QueuedAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint)
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->RemoveBreakpoint(breakpoint);
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


bool QueuedAdapter::RemoveBreakpoints(const std::vector<DebugBreakpoint>& breakpoints)
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&, breakpoints]{
        ret = m_adapter->RemoveBreakpoints(breakpoints);
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


bool QueuedAdapter::ClearAllBreakpoints()
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->ClearAllBreakpoints();
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


std::vector<DebugBreakpoint> QueuedAdapter::GetBreakpointList() const
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    std::vector<DebugBreakpoint> ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->GetBreakpointList();
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


std::string QueuedAdapter::GetRegisterNameByIndex(std::uint32_t index) const
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    std::string ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->GetRegisterNameByIndex(index);
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


std::unordered_map<std::string, DebugRegister> QueuedAdapter::ReadAllRegisters()
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    std::unordered_map<std::string, DebugRegister> ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->ReadAllRegisters();
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


DebugRegister QueuedAdapter::ReadRegister(const std::string& reg)
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    DebugRegister ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->ReadRegister(reg);
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


bool QueuedAdapter::WriteRegister(const std::string& reg, std::uintptr_t value)
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->WriteRegister(reg, value);
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


bool QueuedAdapter::WriteRegister(const DebugRegister& reg, std::uintptr_t value)
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->WriteRegister(reg, value);
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


std::vector<std::string> QueuedAdapter::GetRegisterList() const
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    std::vector<std::string> ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->GetRegisterList();
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


bool QueuedAdapter::ReadMemory(std::uintptr_t address, void* out, std::size_t size)
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->ReadMemory(address, out, size);
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


bool QueuedAdapter::WriteMemory(std::uintptr_t address, const void* out, std::size_t size)
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->WriteMemory(address, out, size);
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


std::vector<DebugModule> QueuedAdapter::GetModuleList()
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    std::vector<DebugModule> ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->GetModuleList();
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


std::string QueuedAdapter::GetTargetArchitecture()
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    std::string ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->GetTargetArchitecture();
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


DebugStopReason QueuedAdapter::StopReason()
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    DebugStopReason ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->StopReason();
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


unsigned long QueuedAdapter::ExecStatus()
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    unsigned long ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->ExecStatus();
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


bool QueuedAdapter::BreakInto()
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->BreakInto();
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


bool QueuedAdapter::Go()
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->Go();
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


bool QueuedAdapter::StepInto()
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->StepInto();
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


bool QueuedAdapter::StepOver()
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->StepOver();
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


bool QueuedAdapter::StepTo(std::uintptr_t address)
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    bool ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->StepTo(address);
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


void QueuedAdapter::Invoke(const std::string& command)
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    Semaphore sem;
    m_queue.push([&]{
        m_adapter->Invoke(command);
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
}


std::uintptr_t QueuedAdapter::GetInstructionOffset()
{
    std::unique_lock<std::mutex> lock(m_queueMutex);

    std::uintptr_t ret;
    Semaphore sem;
    m_queue.push([&]{
        ret = m_adapter->GetInstructionOffset();
        sem.Release();
    });
    lock.unlock();
    sem.Wait();
    return ret;
}


bool QueuedAdapter::SupportFeature(DebugAdapterCapacity feature)
{
    return m_adapter->SupportFeature(feature);
}


void QueuedAdapter::Worker()
{
    while (true)
    {
        std::unique_lock<std::mutex> lock(m_queueMutex);
        if (m_queue.size() != 0)
        {
            std::function<void()> func = m_queue.front();
            m_queue.pop();

            lock.unlock();
            func();
        }
    }
}
