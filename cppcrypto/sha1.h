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

		void init() override;
		void update(const unsigned char* data, size_t len) override;
		void final(unsigned char* hash) override;

		size_t hashsize() const override { return 160; }
		size_t blocksize() const override { return 512; }
		sha1* clone() const override { return new sha1; }
		void clear() override;

	protected:
		void transform(void* m, uint64_t num_blks);

		std::function<void(void*, uint64_t)> transfunc;

		aligned_pod_array<uint32_t, 5, 32> H;
		std::array<unsigned char, 64> m;
		size_t pos;
		uint64_t total;
	};

}

#endif
