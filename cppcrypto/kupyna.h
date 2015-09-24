/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/
#ifndef CPPCRYPTO_KUPYNA_H
#define CPPCRYPTO_KUPYNA_H

#include "crypto_hash.h"
#include <functional>
#include <memory>

namespace cppcrypto
{

	class kupyna256 : public crypto_hash
	{
	public:
		kupyna256();
		~kupyna256();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		int hashbitlen() const { return 256; }

	private:
		void transform();
		void outputTransform();

		uint64_t* h;
		uint8_t* m;
		size_t pos;
		uint64_t total;
	};

	class kupyna512 : public crypto_hash
	{
	public:
		kupyna512();
		~kupyna512();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		int hashbitlen() const { return 512; }

	private:
		void transform();
		void outputTransform();

		uint64_t* h;
		uint8_t* m;
		size_t pos;
		uint64_t total;
	};

}

#endif