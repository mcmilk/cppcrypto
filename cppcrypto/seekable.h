/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SEEKABLE_H
#define CPPCRYPTO_SEEKABLE_H

#include <stdint.h>

namespace cppcrypto
{

	class seekable
	{
	public:
		virtual ~seekable() {}

		virtual void seek(uint64_t pos) = 0;
	};

}

#endif
