/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SKEIN256_H
#define CPPCRYPTO_SKEIN256_H

#include "crypto_hash.h"
#include "alignedarray.h"
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

		size_t hashsize() const { return 256; }
		size_t blocksize() const { return 256; }
		crypto_hash* clone() const { return new skein256_256; }

	protected:
		void transform(void* m, uint64_t num_blks, size_t reallen);

		std::function<void(void*, uint64_t, size_t)> transfunc;
		aligned_pod_array<uint64_t, 4, 32> H;
		uint8_t m[32];
		size_t pos;
		uint64_t total;
		uint64_t tweak[2];
	};

	class skein256_224 : public skein256_256
	{
	public:
		void init();

		size_t hashsize() const { return 224; }
		crypto_hash* clone() const { return new skein256_224; }
	};

	class skein256_160 : public skein256_256
	{
	public:
		void init();

		size_t hashsize() const { return 160; }
		crypto_hash* clone() const { return new skein256_160; }
	};

	class skein256_128 : public skein256_256
	{
	public:
		void init();

		size_t hashsize() const { return 128; }
		crypto_hash* clone() const { return new skein256_128; }
	};

}

#endif
