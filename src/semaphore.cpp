// Copyright (c) 2015-2021 Vector 35 Inc
//

#include "semaphore.h"

void Semaphore::Release()
{
    std::unique_lock<decltype(m_mutex)> lock(m_mutex);
    ++m_count;
    m_cv.notify_one();
}


void Semaphore::Wait()
{
    std::unique_lock<decltype(m_mutex)> lock(m_mutex);
    while (!m_count)
        m_cv.wait(lock);
    --m_count;
}
