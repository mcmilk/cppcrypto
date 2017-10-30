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

		void init() override;
		void update(const unsigned char* data, size_t len) override;
		void final(unsigned char* hash) override;

		size_t hashsize() const override { return 128; }
		size_t blocksize() const override { return 512; }
		md5* clone() const override { return new md5; }
		void clear() override;

	protected:
		void transform(const unsigned char* m, uint64_t num_blks);

		aligned_pod_array<uint32_t, 4, 32> H;
		std::array<unsigned char, 64> m;
		size_t pos;
		uint64_t total;
	};

}

#endif
