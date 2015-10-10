/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/
#ifndef PERFTIMER_H
#define PERFTIMER_H

#include <chrono>

class perftimer
{
public:
	perftimer();
    void reset();
    double elapsed() const;

private:
#ifdef _MSC_VER
	LARGE_INTEGER liHighResCount;
	LARGE_INTEGER liFrequency;
#else
    std::chrono::high_resolution_clock::time_point clk_;
#endif
};

#endif
