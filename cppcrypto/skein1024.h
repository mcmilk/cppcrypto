/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/
#ifndef CPPCRYPTO_SKEIN1024_H
#define CPPCRYPTO_SKEIN1024_H

#include "crypto_hash.h"
#include <functional>

namespace cppcrypto
{

	class skein1024_1024 : public crypto_hash
	{
	public:
		skein1024_1024();
		~skein1024_1024();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		int hashbitlen() const { return 1024; }

	protected:
		void transform(void* m, uint64_t num_blks, size_t reallen);

		uint64_t* H;
		uint8_t m[128];
		size_t pos;
		uint64_t total;
		uint64_t tweak[2];
	};

	class skein1024_512 : public skein1024_1024
	{
	public:
		void init();

		int hashbitlen() const { return 512; }
	};

	class skein1024_384 : public skein1024_1024
	{
	public:
		void init();

		int hashbitlen() const { return 384; }
	};

}

#endif
