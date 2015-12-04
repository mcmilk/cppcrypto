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

		void init();
		void update(const uint8_t* data, size_t len);
		void final(uint8_t* hash);

		size_t hashsize() const { return 512; }
		size_t blocksize() const { return 512; }
		crypto_hash* clone() const { return new jh512; }

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
		void init();

		size_t hashsize() const { return 384; }
		crypto_hash* clone() const { return new jh384; }
	};

	class jh256 : public jh512
	{
	public:
		void init();

		size_t hashsize() const { return 256; }
		crypto_hash* clone() const { return new jh256; }
	};

	class jh224 : public jh512
	{
	public:
		void init();

		size_t hashsize() const { return 224; }
		crypto_hash* clone() const { return new jh224; }
	};

}

#endif
