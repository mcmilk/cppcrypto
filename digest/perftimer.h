/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/
#ifndef PERFTIMER_H
#define PERFTIMER_H

#include <windows.h>

class perftimer
{
public:
	perftimer();
    void reset();
    double elapsed() const;

private:
    LARGE_INTEGER liHighResCount;
    LARGE_INTEGER liFrequency;
};

#endif
