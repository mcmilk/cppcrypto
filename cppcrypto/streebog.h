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

	class streebog512 : public crypto_hash
	{
	public:
		streebog512();
		~streebog512();

		void init() override;
		void update(const uint8_t* data, size_t len) override;
		void final(uint8_t* hash) override;

		size_t hashsize() const override { return 512; }
		size_t blocksize() const override { return 512; }
		streebog512* clone() const override { return new streebog512; }
		void clear() override;

	protected:
		void transform(bool adds = true);

		aligned_pod_array<uint64_t, 8, 32> h;
		aligned_pod_array<uint64_t, 8, 32> S;
		aligned_pod_array<uint8_t, 64, 32> m;
		size_t pos;
		uint64_t total;
	};

	class streebog256 : public streebog512
	{
	public:
		void init() override;

		size_t hashsize() const override { return 256; }
		size_t blocksize() const override { return 512; }
		streebog256* clone() const override { return new streebog256; }
	};

}

#endif
