/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/
#ifndef CPPCRYPTO_BLAKE256_H
#define CPPCRYPTO_BLAKE256_H

#include "crypto_hash.h"
#include <functional>

namespace cppcrypto
{

	class blake256 : public crypto_hash
	{
	public:
		blake256();
		~blake256();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		int hashbitlen() const { return 256; }
		int blockbitlen() const { return 512; }
		crypto_hash* clone() const { return new blake256; }

	protected:
		void transform(bool padding);

		std::function<void(bool)> transfunc;
		uint32_t* H;
		uint32_t s[4];
		uint8_t* m;
		size_t pos;
		uint64_t total;
	};

	class blake512 : public crypto_hash
	{
	public:
		blake512();
		~blake512();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		int hashbitlen() const { return 512; }
		int blockbitlen() const { return 1024; }
		crypto_hash* clone() const { return new blake512; }

	protected:
		void transform(bool padding);

		std::function<void(bool)> transfunc;
		uint64_t* H;
		uint64_t s[4];
		uint8_t* m;
		size_t pos;
		uint64_t total;
	};

	class blake384 : public blake512
	{
	public:
		void init();
		int hashbitlen() const { return 384; }
		crypto_hash* clone() const { return new blake384; }
	};

	class blake224 : public blake256
	{
	public:
		void init();
		int hashbitlen() const { return 224; }
		crypto_hash* clone() const { return new blake224; }
	};

}

#endif
