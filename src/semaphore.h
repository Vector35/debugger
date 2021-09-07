// Copyright (c) 2015-2021 Vector 35 Inc
//

#pragma once

#include <condition_variable>
#include <mutex>

class Semaphore
{
    std::mutex m_mutex;
    std::condition_variable m_cv;
    unsigned long m_count = 0;

public:
    void Release();
    void Wait();
};
