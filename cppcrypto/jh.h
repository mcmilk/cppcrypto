/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_JH_H
#define CPPCRYPTO_JH_H

#include "crypto_hash.h"
#include "alignedarray.h"
#include "jh-impl.h"
#include <array>
#include <functional>

namespace cppcrypto
{
	class jh512 : public crypto_hash
	{
	public:
		jh512();
		~jh512();

		void init() override;
		void update(const uint8_t* data, size_t len) override;
		void final(uint8_t* hash) override;

		size_t hashsize() const override { return 512; }
		size_t blocksize() const override { return 512; }
		jh512* clone() const override { return new jh512; }
		void clear() override;

	protected:
		void transform(void* m, uint64_t num_blks);

		aligned_pod_array<uint64_t, 16, 16> H;
		std::array<uint8_t, 64> m;
		size_t pos;
		uint64_t total;
		aligned_impl_ptr<detail::jh_impl, 32> impl_;
	};

	class jh384 : public jh512
	{
	public:
		void init() override;

		size_t hashsize() const override { return 384; }
		jh384* clone() const override { return new jh384; }
	};

	class jh256 : public jh512
	{
	public:
		void init() override;

		size_t hashsize() const override { return 256; }
		jh256* clone() const override { return new jh256; }
	};

	class jh224 : public jh512
	{
	public:
		void init() override;

		size_t hashsize() const override { return 224; }
		jh224* clone() const override { return new jh224; }
	};

}

#endif
