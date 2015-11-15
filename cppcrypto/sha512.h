/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SHA512_H
#define CPPCRYPTO_SHA512_H

#include "crypto_hash.h"
#include "alignedarray.h"
#include <array>
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

		int hashsize() const { return 512; }
		int blocksize() const { return 1024; }
		crypto_hash* clone() const { return new sha512; }

	protected:
		void transform(void* m, uint64_t num_blks);

		std::function<void(void*, uint64_t)> transfunc;
		aligned_pod_array<uint64_t, 8, 32> H;
		std::array<uint8_t, 128> m;
		size_t pos;
		uint64_t total;
	};

	class sha512_256 : public sha512
	{
	public:
		void init();

		int hashsize() const { return 256; }
		crypto_hash* clone() const { return new sha512_256; }
	};

	class sha512_224 : public sha512
	{
	public:
		void init();

		int hashsize() const { return 224; }
		crypto_hash* clone() const { return new sha512_224; }
	};

	class sha384 : public sha512
	{
	public:
		void init();

		int hashsize() const { return 384; }
		crypto_hash* clone() const { return new sha384; }
	};

}

#endif
