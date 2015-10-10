/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/

#ifndef CPPCRYPTO_SHA256_H
#define CPPCRYPTO_SHA256_H

#include "crypto_hash.h"
#include <functional>

namespace cppcrypto
{

	class sha256 : public crypto_hash
	{
	public:
		sha256();
		~sha256();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		int hashbitlen() const { return 256; }
		int blockbitlen() const { return 512; }
		crypto_hash* clone() const { return new sha256; }

	protected:
		void transform(void* m, uint64_t num_blks);

		std::function<void(void*, uint64_t)> transfunc;
		uint32_t* H;
		uint8_t m[64];
		size_t pos;
		uint64_t total;
	};

	class sha224 : public sha256
	{
	public:
		void init();

		int hashbitlen() const { return 224; }
		crypto_hash* clone() const { return new sha224; }
	};

}

#endif
