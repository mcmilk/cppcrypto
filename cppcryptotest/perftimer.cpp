#include "stdafx.h"
#include "perftimer.h"

#ifndef _MSC_VER
perftimer::perftimer()
{
    reset();
}

void perftimer::reset()
{
    clk_ = std::chrono::high_resolution_clock::now();
}

double perftimer::elapsed() const
{
  std::chrono::duration<double> dura = std::chrono::high_resolution_clock::now() - clk_;
	return dura.count();
}
#else
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
#endif

