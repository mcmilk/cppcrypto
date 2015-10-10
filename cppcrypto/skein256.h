/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#ifndef CPPCRYPTO_SKEIN256_H
#define CPPCRYPTO_SKEIN256_H

#include "crypto_hash.h"
#include <functional>

namespace cppcrypto
{

	class skein256_256 : public crypto_hash
	{
	public:
		skein256_256();
		~skein256_256();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		int hashbitlen() const { return 256; }
		int blockbitlen() const { return 256; }
		crypto_hash* clone() const { return new skein256_256; }

	protected:
		void transform(void* m, uint64_t num_blks, size_t reallen);

		std::function<void(void*, uint64_t, size_t)> transfunc;
		uint64_t* H;
		uint8_t m[32];
		size_t pos;
		uint64_t total;
		uint64_t tweak[2];
	};

	class skein256_224 : public skein256_256
	{
	public:
		void init();

		int hashbitlen() const { return 224; }
		crypto_hash* clone() const { return new skein256_224; }
	};

	class skein256_160 : public skein256_256
	{
	public:
		void init();

		int hashbitlen() const { return 160; }
		crypto_hash* clone() const { return new skein256_160; }
	};

	class skein256_128 : public skein256_256
	{
	public:
		void init();

		int hashbitlen() const { return 128; }
		crypto_hash* clone() const { return new skein256_128; }
	};

}

#endif
