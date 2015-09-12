/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#ifndef CPPCRYPTO_SKEIN512_H
#define CPPCRYPTO_SKEIN512_H

#include "crypto_hash.h"
#include <functional>

namespace cppcrypto
{

	class skein512_512 : public crypto_hash
	{
	public:
		skein512_512();
		~skein512_512();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		int hashbitlen() const { return 512; }

	protected:
		void transform(void* m, uint64_t num_blks, size_t reallen);
		std::function<void(void*, uint64_t, size_t)> transfunc;

		uint64_t* H;
		uint8_t m[64];
		size_t pos;
		uint64_t total;
		uint64_t tweak[2];
	};

	class skein512_256 : public skein512_512
	{
	public:
		void init();

		int hashbitlen() const { return 256; }
	};

	class skein512_384 : public skein512_512
	{
	public:
		void init();

		int hashbitlen() const { return 384; }
	};

	class skein512_224 : public skein512_512
	{
	public:
		void init();

		int hashbitlen() const { return 224; }
	};

}

#endif