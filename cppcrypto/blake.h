/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_BLAKE256_H
#define CPPCRYPTO_BLAKE256_H

#include "crypto_hash.h"
#include "alignedarray.h"
#include <functional>
#include <array>

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

		size_t hashsize() const { return 256; }
		size_t blocksize() const { return 512; }
		crypto_hash* clone() const { return new blake256; }
		void clear();

	protected:
		void transform(bool padding);

		std::function<void(bool)> transfunc;
		aligned_pod_array<uint32_t, 8, 64> H;
		std::array<uint32_t, 4> s;
		aligned_pod_array<uint8_t, 64, 64> m;
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

		size_t hashsize() const { return 512; }
		size_t blocksize() const { return 1024; }
		crypto_hash* clone() const { return new blake512; }
		void clear();

	protected:
		void transform(bool padding);

		std::function<void(bool)> transfunc;
		aligned_pod_array<uint64_t, 8, 64> H;
		std::array<uint64_t, 4> s;
		aligned_pod_array<uint8_t, 128, 64> m;
		size_t pos;
		uint64_t total;
	};

	class blake384 : public blake512
	{
	public:
		void init();
		size_t hashsize() const { return 384; }
		crypto_hash* clone() const { return new blake384; }
	};

	class blake224 : public blake256
	{
	public:
		void init();
		size_t hashsize() const { return 224; }
		crypto_hash* clone() const { return new blake224; }
	};

}

#endif
