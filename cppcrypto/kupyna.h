/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_KUPYNA_H
#define CPPCRYPTO_KUPYNA_H

#include "crypto_hash.h"
#include "alignedarray.h"
#include <functional>
#include <memory>

namespace cppcrypto
{

	class kupyna : public crypto_hash
	{
	public:
		kupyna(size_t hashsize);
		~kupyna();

		void init() override;
		void update(const unsigned char* data, size_t len) override;
		void final(unsigned char* hash) override;

		size_t hashsize() const override { return hs; }
		size_t blocksize() const override { return hs > 256 ? 1024 : 512; }
		kupyna* clone() const override { return new kupyna(hs); }
		void clear() override;

	private:
		aligned_pod_array<uint64_t, 16, 32> h;
		aligned_pod_array<unsigned char, 128, 32> m;
		size_t hs;
		size_t pos;
		uint64_t total;
	};

}

#endif
