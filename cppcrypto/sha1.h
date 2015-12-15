/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_SHA1_H
#define CPPCRYPTO_SHA1_H

#include "crypto_hash.h"
#include "alignedarray.h"
#include <array>
#include <functional>

namespace cppcrypto
{

	class sha1 : public crypto_hash
	{
	public:
		sha1();
		~sha1();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		size_t hashsize() const { return 160; }
		size_t blocksize() const { return 512; }
		crypto_hash* clone() const { return new sha1; }
		void clear();

	protected:
		void transform(void* m, uint64_t num_blks);

		std::function<void(void*, uint64_t)> transfunc;

		aligned_pod_array<uint32_t, 5, 32> H;
		std::array<uint8_t, 64> m;
		size_t pos;
		uint64_t total;
	};

}

#endif