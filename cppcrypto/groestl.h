/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/
#ifndef CPPCRYPTO_GROESTL_H
#define CPPCRYPTO_GROESTL_H

#include "crypto_hash.h"
#include <functional>
#include <memory>
#include "groestl-impl.h"

namespace cppcrypto
{

	class groestl256 : public crypto_hash
	{
	public:
		groestl256();
		~groestl256();

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
		groestl_impl* impl_;
	};

	class groestl512 : public crypto_hash
	{
	public:
		groestl512();
		~groestl512();

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
		groestl_impl* impl_;
	};

	class groestl384 : public groestl512
	{
	public:
		int hashbitlen() const { return 384; }
	};

	class groestl224 : public groestl256
	{
	public:
		int hashbitlen() const { return 224; }
	};

}

#endif
