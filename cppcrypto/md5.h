/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_MD5_H
#define CPPCRYPTO_MD5_H

#include "crypto_hash.h"
#include "alignedarray.h"
#include <array>
#include <functional>

namespace cppcrypto
{

	class md5 : public crypto_hash
	{
	public:
		md5();
		~md5();

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		int hashsize() const { return 128; }
		int blocksize() const { return 512; }
		crypto_hash* clone() const { return new md5; }

	protected:
		void transform(const uint8_t* m, uint64_t num_blks);

		aligned_pod_array<uint32_t, 4, 32> H;
		std::array<uint8_t, 64> m;
		size_t pos;
		uint64_t total;
	};

}

#endif
