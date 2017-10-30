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
	class jh : public crypto_hash
	{
	public:
		jh(size_t hashsize);
		~jh();

		void init() override;
		void update(const unsigned char* data, size_t len) override;
		void final(unsigned char* hash) override;

		size_t hashsize() const override { return hs; }
		size_t blocksize() const override { return 512; }
		jh* clone() const override { return new jh(hs); }
		void clear() override;

	protected:
		void transform(void* m, uint64_t num_blks);

		aligned_pod_array<uint64_t, 16, 16> H;
		std::array<unsigned char, 64> m;
		size_t hs;
		size_t pos;
		uint64_t total;
		aligned_impl_ptr<detail::jh_impl, 32> impl_;
	};

}

#endif
