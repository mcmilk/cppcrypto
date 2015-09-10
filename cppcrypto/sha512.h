/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#ifndef CPPCRYPTO_SHA512_H
#define CPPCRYPTO_SHA512_H

#include "crypto_hash.h"
#include <functional>

namespace cppcrypto
{

	class sha512 : public crypto_hash
	{
	public:
		sha512();
		~sha512();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		int hashbitlen() const { return 512; }

	protected:
		void transform(void* m, uint64_t num_blks);

		std::function<void(void*, uint64_t)> transfunc;
		uint64_t* H;
		uint8_t m[128];
		size_t pos;
		uint64_t total;
	};

	class sha512_256 : public sha512
	{
	public:
		void init();

		int hashbitlen() const { return 256; }
	};

	class sha512_224 : public sha512
	{
	public:
		void init();

		int hashbitlen() const { return 224; }
	};

	class sha384 : public sha512
	{
	public:
		void init();

		int hashbitlen() const { return 384; }
	};

}

#endif
