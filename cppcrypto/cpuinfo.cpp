/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/
#include <vector>
#include <bitset>
#include <array>
#include <string>
#include "cpuinfo.h"

namespace cppcrypto
{

const cpu_info::cpu_info_impl cpu_info::impl_;


cpu_info::cpu_info_impl::cpu_info_impl()
	: ecx1_{ 0 }, edx1_{ 0 }, ebx7_{ 0 }, ecx7_{ 0 }, ecx81_{ 0 }, edx81_{ 0 }
{
	std::array<int, 4> cpui;

	__cpuid(cpui.data(), 0);
	int ids = cpui[0];

	if (ids >= 1)
	{
		__cpuidex(cpui.data(), 1, 0);
		ecx1_ = cpui[2];
		edx1_ = cpui[3];
	}

	if (ids >= 7)
	{
		__cpuidex(cpui.data(), 7, 0);
		ebx7_ = cpui[1];
		ecx7_ = cpui[2];
	}

	__cpuid(cpui.data(), 0x80000000);
	int extended_ids = cpui[0];

	if (extended_ids >= 0x80000001)
	{
		__cpuidex(cpui.data(), 1, 0);
		ecx81_ = cpui[2];
		edx81_ = cpui[3];
	}

};



}

