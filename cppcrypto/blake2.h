/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_BLAKE2_H
#define CPPCRYPTO_BLAKE2_H

#include "crypto_hash.h"
#include "alignedarray.h"
#include <functional>
#include <array>

namespace cppcrypto
{
	class blake2b : public crypto_hash
	{
	public:
		blake2b(size_t hashsize);
		~blake2b();

		void init() override;
		void update(const unsigned char* data, size_t len) override;
		void final(unsigned char* hash) override;

		size_t hashsize() const override { return hs; }
		size_t blocksize() const override { return 1024; }
		blake2b* clone() const override { return new blake2b(hs); }
		void clear() override;

	protected:
		void transform(bool padding);

		std::function<void(bool)> transfunc;
		aligned_pod_array<uint64_t, 8, 64> H;
		aligned_pod_array<unsigned char, 128, 64> m;
		size_t pos;
		uint64_t total;
		size_t hs;
	};

	class blake2s : public crypto_hash
	{
	public:
		blake2s(size_t hashsize);
		~blake2s();

		void init() override;
		void update(const unsigned char* data, size_t len) override;
		void final(unsigned char* hash) override;

		size_t hashsize() const override { return hs; }
		size_t blocksize() const override { return 512; }
		blake2s* clone() const override { return new blake2s(hs); }
		void clear() override;

	protected:
		void transform(bool padding);

		std::function<void(bool)> transfunc;
		aligned_pod_array<uint32_t, 8, 64> H;
		aligned_pod_array<unsigned char, 64, 64> m;
		size_t pos;
		uint64_t total;
		size_t hs;
	};

}

#endif

