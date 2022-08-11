/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_STREEBOG_H
#define CPPCRYPTO_STREEBOG_H

#include "crypto_hash.h"
#include "alignedarray.h"
#include <functional>
#include <memory>

namespace cppcrypto
{

	class streebog : public crypto_hash
	{
	public:
		streebog(size_t hashsize);
		~streebog();

		void init() override;
		void update(const unsigned char* data, size_t len) override;
		void final(unsigned char* hash) override;

		size_t hashsize() const override { return hs; }
		size_t blocksize() const override { return 512; }
		streebog* clone() const override { return new streebog(hs); }
		void clear() override;

	protected:
		void transform(bool adds = true);

		aligned_pod_array<uint64_t, 8, 32> h;
		aligned_pod_array<uint64_t, 8, 32> S;
		aligned_pod_array<unsigned char, 64, 32> m;
		size_t hs;
		size_t pos;
		uint64_t total;
	};

}

#endif
