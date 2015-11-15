/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SHA256_H
#define CPPCRYPTO_SHA256_H

#include "crypto_hash.h"
#include "alignedarray.h"
#include <array>
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

		int hashsize() const { return 256; }
		int blocksize() const { return 512; }
		crypto_hash* clone() const { return new sha256; }

	protected:
		void transform(void* m, uint64_t num_blks);

		std::function<void(void*, uint64_t)> transfunc;

		aligned_pod_array<uint32_t, 8, 32> H;
		std::array<uint8_t, 64> m;
		size_t pos;
		uint64_t total;
	};

	class sha224 : public sha256
	{
	public:
		void init();

		int hashsize() const { return 224; }
		crypto_hash* clone() const { return new sha224; }
	};

}

#endif
