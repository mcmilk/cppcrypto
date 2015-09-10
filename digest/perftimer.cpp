#include "stdafx.h"
#include "perftimer.h"


perftimer::perftimer()
{
    QueryPerformanceFrequency(&liFrequency);
    reset();
}

void perftimer::reset()
{
    QueryPerformanceCounter(&liHighResCount);
}

double perftimer::elapsed() const
{
  LARGE_INTEGER     li_count;

    if (!QueryPerformanceCounter(&li_count))
        return -1;

    return static_cast<double>(li_count.QuadPart - liHighResCount.QuadPart)
           / static_cast<double>(liFrequency.QuadPart);
}


